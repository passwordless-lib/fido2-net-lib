using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Serialization;

using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// Resolves display names/icons from a local JSON file, in the shape used by
/// <see href="https://github.com/passkeydeveloper/passkey-authenticator-aaguids"/>: a flat object keyed by
/// AAGUID, each entry carrying a <c>name</c> and <c>icon_light</c>/<c>icon_dark</c>.
/// </summary>
/// <remarks>
/// For offline use, or for a Relying Party's own maintained list of AAGUIDs not covered by
/// <see cref="ConvenienceMetadataService"/>. Like that service, this carries no trust information --
/// see <see cref="IAuthenticatorDisplayMetadataService"/>. The file is read once, on first use; a missing or
/// unreadable file is logged and answers every lookup with <see langword="null"/>.
/// </remarks>
public sealed class FileSystemDisplayMetadataRepository : IAuthenticatorDisplayMetadataService
{
    private readonly string _filePath;
    private readonly ILogger<FileSystemDisplayMetadataRepository>? _logger;
    private readonly Lazy<Task<Dictionary<Guid, AuthenticatorDisplayInfo>>> _entries;

    /// <summary>
    /// Initializes the repository.
    /// </summary>
    /// <param name="filePath">The path to the local display-metadata JSON file.</param>
    /// <param name="logger">Where a missing or unreadable file is reported (event IDs 1303-1304), or <see langword="null"/>.</param>
    public FileSystemDisplayMetadataRepository(string filePath, ILogger<FileSystemDisplayMetadataRepository>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        _filePath = filePath;
        _logger = logger;
        _entries = new(LoadAsync, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <inheritdoc/>
    public async Task<AuthenticatorDisplayInfo?> GetDisplayInfoAsync(Guid aaguid, CancellationToken cancellationToken = default)
    {
        var entries = await _entries.Value.WaitAsync(cancellationToken);
        return entries.TryGetValue(aaguid, out var info) ? info : null;
    }

    private async Task<Dictionary<Guid, AuthenticatorDisplayInfo>> LoadAsync()
    {
        var entries = new Dictionary<Guid, AuthenticatorDisplayInfo>();

        if (!File.Exists(_filePath))
        {
            _logger?.LocalFileMissing(_filePath);
            return entries;
        }

        try
        {
            await using var fileStream = new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, useAsync: true);

            var raw = await JsonSerializer.DeserializeAsync(
                fileStream,
                FidoSerializerContext.Default.DictionaryStringLocalAuthenticatorDisplayEntry) ?? [];

            foreach (var (key, entry) in raw)
            {
                if (entry is not null && Guid.TryParse(key, out var aaguid))
                {
                    entries[aaguid] = new AuthenticatorDisplayInfo(
                        AuthenticatorDisplayInfo.SanitizeName(entry.Name),
                        AuthenticatorDisplayInfo.SanitizeIcon(entry.IconLight),
                        AuthenticatorDisplayInfo.SanitizeIcon(entry.IconDark));
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            _logger?.LocalFileUnreadable(ex, _filePath);
            entries.Clear();
        }

        return entries;
    }
}
