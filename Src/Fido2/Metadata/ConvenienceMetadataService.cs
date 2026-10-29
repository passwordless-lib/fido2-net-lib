using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Serialization;

using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// Resolves display names and icons from the FIDO Alliance Convenience Metadata Service at
/// <see href="https://c-mds.fidoalliance.org/"/>
/// (<see href="https://fidoalliance.org/specs/mds/fido-convenience-metadata-service-v1.0-ps-20250521.html">spec</see>).
/// </summary>
/// <remarks>
/// <para>
/// The data is display-only and is not used for trust decisions -- see <see cref="IAuthenticatorDisplayMetadataService"/>.
/// If the document arrives as a signed BLOB, its payload is read without checking the signature.
/// </para>
/// <para>
/// The whole document is downloaded and kept in memory, then re-checked every
/// <see cref="DisplayMetadataOptions.RefreshInterval"/> with the copy's serial number
/// (<c>?localCopySerial=</c>), so an unchanged document is answered with 304 rather than downloaded again. Only one
/// download runs at a time; while it does, callers are answered from the previous copy. A failed download is logged
/// and not retried for <see cref="DisplayMetadataOptions.RetryAfterFailure"/>, and lookups never throw because of
/// it -- they return the last good answer, or <see langword="null"/>.
/// </para>
/// </remarks>
public sealed class ConvenienceMetadataService : IAuthenticatorDisplayMetadataService
{
    private static readonly IReadOnlyDictionary<Guid, AuthenticatorDisplayInfo> s_empty = new Dictionary<Guid, AuthenticatorDisplayInfo>();

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly DisplayMetadataOptions _options;
    private readonly ILogger<ConvenienceMetadataService>? _logger;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    private sealed record Snapshot(IReadOnlyDictionary<Guid, AuthenticatorDisplayInfo> Entries, int? Serial);

    private volatile Snapshot? _snapshot;
    private long _nextRefreshAtUtcTicks;

    /// <summary>
    /// Initializes the service.
    /// </summary>
    /// <param name="httpClientFactory">Creates the client (named after this type) the document is downloaded with.</param>
    /// <param name="options">Where to download from and how often; <see langword="null"/> for the defaults.</param>
    /// <param name="logger">Where downloads and failures are logged (event IDs 1300-1302), or <see langword="null"/>.</param>
    /// <param name="timeProvider">The clock refresh times are computed against; <see langword="null"/> for the system clock.</param>
    public ConvenienceMetadataService(
        IHttpClientFactory httpClientFactory,
        DisplayMetadataOptions? options = null,
        ILogger<ConvenienceMetadataService>? logger = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientFactory);

        _httpClientFactory = httpClientFactory;
        _options = options ?? new DisplayMetadataOptions();
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc/>
    public async Task<AuthenticatorDisplayInfo?> GetDisplayInfoAsync(Guid aaguid, CancellationToken cancellationToken = default)
    {
        var entries = await GetEntriesAsync(cancellationToken);
        return entries.TryGetValue(aaguid, out var info) ? info : null;
    }

    private bool IsRefreshDue() => _timeProvider.GetUtcNow().UtcTicks >= Volatile.Read(ref _nextRefreshAtUtcTicks);

    private async Task<IReadOnlyDictionary<Guid, AuthenticatorDisplayInfo>> GetEntriesAsync(CancellationToken cancellationToken)
    {
        var current = _snapshot;

        if (!IsRefreshDue())
            return current?.Entries ?? s_empty;

        // With a copy in hand, don't queue behind a refresh another caller is already running: answer from the copy.
        if (current is not null)
        {
            if (!await _refreshLock.WaitAsync(0, cancellationToken))
                return current.Entries;
        }
        else
        {
            await _refreshLock.WaitAsync(cancellationToken);
        }

        try
        {
            if (IsRefreshDue())
                await RefreshAsync(cancellationToken);

            return _snapshot?.Entries ?? s_empty;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        var previous = _snapshot;
        var uri = _options.ConvenienceMetadataServiceUrl ?? DisplayMetadataOptions.DefaultConvenienceMetadataServiceUrl;

        try
        {
            var requestUri = uri;
            if (previous?.Serial is int serial)
            {
                var builder = new UriBuilder(uri);
                var query = builder.Query.TrimStart('?');
                builder.Query = (query.Length > 0 ? query + "&" : "") + "localCopySerial=" + serial;
                requestUri = builder.Uri;
            }

            var httpClient = _httpClientFactory.CreateClient(nameof(ConvenienceMetadataService));
            // ResponseContentRead buffers the body before returning, so this bounds the download itself.
            httpClient.MaxResponseContentBufferSize = _options.MaxDocumentBytes;

            using var response = await httpClient.GetAsync(requestUri, HttpCompletionOption.ResponseContentRead, cancellationToken);

            if (response.StatusCode == HttpStatusCode.NotModified && previous is not null)
            {
                _logger?.ConvenienceDocumentNotModified(previous.Serial);
            }
            else
            {
                response.EnsureSuccessStatusCode();

                var body = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                var (documentSerial, entries) = Parse(body);

                documentSerial ??= SerialFromETag(response);

                _snapshot = new Snapshot(entries, documentSerial);
                _logger?.ConvenienceDocumentDownloaded(documentSerial, uri, entries.Count);
            }

            Volatile.Write(ref _nextRefreshAtUtcTicks, (_timeProvider.GetUtcNow() + _options.RefreshInterval).UtcTicks);
        }
        catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
        {
            var retryAt = _timeProvider.GetUtcNow() + _options.RetryAfterFailure;
            Volatile.Write(ref _nextRefreshAtUtcTicks, retryAt.UtcTicks);
            _logger?.ConvenienceDocumentFailed(ex, uri, retryAt);
        }
    }

    /// <summary>
    /// The serial number the service puts in the ETag. It sends it unquoted (<c>ETag: 286</c>), which the typed
    /// <see cref="System.Net.Http.Headers.HttpResponseHeaders.ETag"/> rejects as malformed, so the raw value is read.
    /// </summary>
    private static int? SerialFromETag(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("ETag", out var values))
            return null;

        foreach (var value in values)
        {
            var tag = value.Trim();
            if (tag.StartsWith("W/", StringComparison.Ordinal))
                tag = tag[2..];

            if (int.TryParse(tag.Trim('"'), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var serial))
                return serial;
        }

        return null;
    }

    /// <summary>
    /// Reads a Convenience Metadata Service document: a <c>ConvenienceMetadataPayload</c> JSON object -- a numeric
    /// serial number <c>no</c> plus one <c>ConvenienceDetails</c> member per AAGUID -- either bare or as the payload
    /// of a JWS compact serialization.
    /// </summary>
    /// <exception cref="FormatException">The document is neither.</exception>
    internal static (int? Serial, IReadOnlyDictionary<Guid, AuthenticatorDisplayInfo> Entries) Parse(ReadOnlySpan<byte> body)
    {
        body = body.Trim(" \t\r\n"u8);

        byte[] json;
        if (body.Length > 0 && body[0] == (byte)'{')
        {
            json = body.ToArray();
        }
        else
        {
            var firstDot = body.IndexOf((byte)'.');
            var lastDot = body.LastIndexOf((byte)'.');
            if (firstDot <= 0 || lastDot <= firstDot)
                throw new FormatException("The Convenience Metadata Service document is neither JSON nor a JWS.");

            json = Base64Url.DecodeFromUtf8(body[(firstDot + 1)..lastDot]);
        }

        using var document = JsonDocument.Parse(json);

        if (document.RootElement.ValueKind is not JsonValueKind.Object)
            throw new FormatException("The Convenience Metadata Service payload is not a JSON object.");

        int? serial = null;
        var entries = new Dictionary<Guid, AuthenticatorDisplayInfo>();

        foreach (var member in document.RootElement.EnumerateObject())
        {
            if (member.NameEquals("no"u8))
            {
                if (member.Value.ValueKind is JsonValueKind.Number && member.Value.TryGetInt32(out var no))
                    serial = no;
                continue;
            }

            if (member.Value.ValueKind is not JsonValueKind.Object || !Guid.TryParse(member.Name, out var aaguid))
                continue;

            var entry = member.Value.Deserialize(FidoSerializerContext.Default.ConvenienceMetadataEntry);
            if (entry is null)
                continue;

            // The spec: "the icon is more specific than the provider logo and should be shown if present."
            entries[aaguid] = new AuthenticatorDisplayInfo(
                AuthenticatorDisplayInfo.PickName(entry.FriendlyNames),
                AuthenticatorDisplayInfo.SanitizeIcon(entry.Icon) ?? AuthenticatorDisplayInfo.SanitizeIcon(entry.ProviderLogoLight),
                AuthenticatorDisplayInfo.SanitizeIcon(entry.IconDark) ?? AuthenticatorDisplayInfo.SanitizeIcon(entry.ProviderLogoDark))
            {
                FriendlyNames = entry.FriendlyNames
            };
        }

        return (serial, entries);
    }
}
