using System;
using System.Buffers.Text;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Serialization;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Fido2NetLib;

/// <summary>
/// Fetches, validates, and caches the FIDO Alliance Metadata Service (MDS) v3.1.1 BLOB.
/// </summary>
/// <remarks>
/// This type is registered as a singleton by <c>AddFidoMetadataRepository</c> so that the conditional-GET
/// (ETag/If-None-Match) state below is retained across fetches -- MDS publishes an ETag on the BLOB response,
/// and reusing it lets a re-fetch (once the caller's own cache has expired) receive a 304 Not Modified instead
/// of re-downloading the full multi-megabyte BLOB when it hasn't actually changed.
/// </remarks>
public sealed class Fido2MetadataServiceRepository(IHttpClientFactory httpClientFactory) : IMetadataRepository
{
    private static ReadOnlySpan<byte> ROOT_CERT =>
        "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G"u8 +
        "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp"u8 +
        "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4"u8 +
        "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG"u8 +
        "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI"u8 +
        "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8"u8 +
        "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT"u8 +
        "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm"u8 +
        "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd"u8 +
        "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ"u8 +
        "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw"u8 +
        "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o"u8 +
        "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU"u8 +
        "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp"u8 +
        "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK"u8 +
        "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX"u8 +
        "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs"u8 +
        "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH"u8 +
        "WD9f"u8;

    private const int MaxRetryAttempts = 4;
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(30);

    // Asymmetric signing algorithms accepted for the BLOB JWT. Explicitly enumerated as defense in
    // depth against alg-confusion attacks (e.g. "none" or a symmetric alg substituted for the
    // certificate's public key material), rather than relying solely on key-type inference.
    private static readonly string[] AllowedJwsAlgorithms =
    [
        SecurityAlgorithms.EcdsaSha256,
        SecurityAlgorithms.EcdsaSha384,
        SecurityAlgorithms.EcdsaSha512,
        SecurityAlgorithms.RsaSha256,
        SecurityAlgorithms.RsaSha384,
        SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256,
        SecurityAlgorithms.RsaSsaPssSha384,
        SecurityAlgorithms.RsaSsaPssSha512,
    ];

    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

    private sealed record CachedRawBlob(EntityTagHeaderValue ETag, string RawBlob);

    // Set after each successful (non-304) fetch that returns an ETag, and read at the start of the next fetch
    // to conditionally re-validate. Plain field access is fine here: a torn read just means an occasional
    // fetch skips the conditional GET optimization, not a correctness issue.
    private CachedRawBlob? _cachedRawBlob;

    public Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
    {
        return Task.FromResult<MetadataStatement?>(entry.MetadataStatement);
    }

    public async Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
    {
        var rawBLOB = await GetRawBlobAsync(cancellationToken);
        using var rootCert = X509CertificateHelper.CreateFromBase64String(ROOT_CERT);
        return await DeserializeAndValidateBlobAsync(rawBLOB, rootCert, cancellationToken);
    }

    private async Task<string> GetRawBlobAsync(CancellationToken cancellationToken)
    {
        var httpClient = _httpClientFactory.CreateClient(nameof(Fido2MetadataServiceRepository));
        var cached = _cachedRawBlob;

        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/");
            if (cached is not null)
            {
                request.Headers.IfNoneMatch.Add(cached.ETag);
            }

            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            if (response.StatusCode is HttpStatusCode.NotModified && cached is not null)
            {
                return cached.RawBlob;
            }

            if (response.IsSuccessStatusCode)
            {
                var rawBlob = await response.Content.ReadAsStringAsync(cancellationToken);

                _cachedRawBlob = response.Headers.ETag is { } etag
                    ? new CachedRawBlob(etag, rawBlob)
                    : null;

                return rawBlob;
            }

            var isThrottled = response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable;

            if (!isThrottled || attempt >= MaxRetryAttempts)
            {
                throw new Fido2MetadataException(
                    $"Failed to retrieve MDS BLOB: server returned {(int)response.StatusCode} {response.StatusCode}" +
                    (isThrottled ? $" after {attempt + 1} attempts" : string.Empty));
            }

            var delay = GetRetryDelay(response.Headers.RetryAfter, attempt);
            await Task.Delay(delay, cancellationToken);
        }
    }

    private static TimeSpan GetRetryDelay(System.Net.Http.Headers.RetryConditionHeaderValue? retryAfter, int attempt)
    {
        TimeSpan? serverRequestedDelay = retryAfter switch
        {
            { Delta: { } delta } => delta,
            { Date: { } date } => date - DateTimeOffset.UtcNow,
            _ => null
        };

        // fall back to exponential backoff with jitter when the server didn't specify Retry-After
        var backoff = serverRequestedDelay is { } d && d > TimeSpan.Zero
            ? d
            : TimeSpan.FromSeconds(Math.Pow(2, attempt)) + TimeSpan.FromMilliseconds(Random.Shared.Next(0, 250));

        return backoff > MaxRetryDelay ? MaxRetryDelay : backoff;
    }

    // internal for testing: the trust root is injected so a self-built chain can be validated without the
    // real GlobalSign root. Production always passes the bundled ROOT_CERT.
    internal async Task<MetadataBLOBPayload> DeserializeAndValidateBlobAsync(string rawBLOBJwt, X509Certificate2 rootCert, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawBLOBJwt);

        var jwtParts = rawBLOBJwt.Split('.');

        if (jwtParts.Length != 3)
            throw new ArgumentException("The JWT does not have the 3 expected components");

        var blobHeaderString = jwtParts[0];
        using var blobHeaderDoc = JsonDocument.Parse(Base64Url.DecodeFromChars(blobHeaderString));
        var blobHeader = blobHeaderDoc.RootElement;

        string blobAlg = blobHeader.TryGetProperty("alg", out var algEl)
            ? algEl.GetString()!
            : throw new Fido2MetadataException("No alg value was present in the BLOB header");

        if (Array.IndexOf(AllowedJwsAlgorithms, blobAlg) < 0)
        {
            throw new Fido2MetadataException($"Unsupported alg value '{blobAlg}' was present in the BLOB header");
        }


        if (!blobHeader.TryGetProperty("x5c", out var x5cEl))
        {
            throw new Fido2MetadataException("No x5c value was present in the BLOB header");
        }

        if (!x5cEl.TryDecodeArrayOfBase64EncodedBytes(out var x5cRawKeys))
        {
            throw new Fido2MetadataException("The x5c value in the BLOB header is malformed");
        }

        if (x5cRawKeys.Length is 0)
        {
            throw new Fido2MetadataException("No x5c keys were present in the BLOB header");
        }

        var blobCerts = new X509Certificate2[x5cRawKeys.Length];
        var keys = new SecurityKey[x5cRawKeys.Length];

        for (int i = 0; i < blobCerts.Length; i++)
        {
            var cert = X509CertificateHelper.CreateFromRawData(x5cRawKeys[i]);

            blobCerts[i] = cert;

            if (cert.GetECDsaPublicKey() is ECDsa ecdsaPublicKey)
            {
                keys[i] = new ECDsaSecurityKey(ecdsaPublicKey);
            }
            else if (cert.GetRSAPublicKey() is RSA rsaPublicKey)
            {
                keys[i] = new RsaSecurityKey(rsaPublicKey);
            }
            else
            {
                throw new Fido2MetadataException("Unknown certificate algorithm");
            }
        }
        var blobPublicKeys = keys.ToArray(); // defensive copy

        var certChain = new X509Chain();
        certChain.ChainPolicy.ExtraStore.Add(rootCert);
        certChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        var tokenHandler = new JsonWebTokenHandler
        {
            // 250k isn't enough bytes for conformance test tool
            // https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/1097
            MaximumTokenSizeInBytes = rawBLOBJwt.Length
        };

        var validateTokenResult = await tokenHandler.ValidateTokenAsync(rawBLOBJwt, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = blobPublicKeys,
            ValidAlgorithms = AllowedJwsAlgorithms
        }).ConfigureAwait(false);

        if (!validateTokenResult.IsValid)
        {
            throw new Fido2VerificationException("rawBLOBJwt is not valid");
        }

        if (blobCerts.Length > 1)
        {
            certChain.ChainPolicy.ExtraStore.AddRange(blobCerts.Skip(1).ToArray());
        }

        var certChainIsValid = certChain.Build(blobCerts[0]);

        // The BLOB signing chain MUST terminate at the bundled FIDO Alliance root, regardless of the host's
        // trust store. X509Chain's default System trust mode returns true for a chain to ANY publicly-trusted
        // CA, so a successful Build() alone would accept a BLOB signed under an unrelated public CA. Pin the
        // terminal certificate to the downloaded root.
        bool pinnedToFidoRoot = certChain.ChainElements.Count > 0
            && rootCert.Thumbprint.Equals(certChain.ChainElements[^1].Certificate.Thumbprint, StringComparison.Ordinal);

        if (certChainIsValid)
        {
            if (!pinnedToFidoRoot)
                throw new Fido2VerificationException("The MDS BLOB signing certificate chain does not terminate at the FIDO Alliance root");
        }
        else
        {
            // The host does not trust the FIDO root (the usual case outside the browser PKI). Validate the chain
            // manually against the pinned root before trusting -- or fetching anything named by -- its certificates.
            #pragma warning disable format
            bool manualChainIsValid =
                pinnedToFidoRoot &&
                // the chain accounts for exactly what was in x5c plus the root we added
                certChain.ChainElements.Count == (x5cRawKeys.Length + 1) &&
                // and the root cert has exactly one status, UntrustedRoot
                certChain.ChainElements[^1].ChainElementStatus is [{ Status: X509ChainStatusFlags.UntrustedRoot }];
            #pragma warning restore format

            if (manualChainIsValid)
            {
                for (int i = 0; i < certChain.ChainElements.Count - 1; i++)
                {
                    // every non-root cert must carry no status of its own
                    if (certChain.ChainElements[i].ChainElementStatus.Length != 0)
                        manualChainIsValid = false;
                }
            }

            if (!manualChainIsValid)
                throw new Fido2VerificationException("Failed to validate cert chain while parsing BLOB");

            // Only now that the chain is known to pin to the FIDO root do we consult revocation. The CRL
            // distribution point is taken from the certificate, so it is restricted to http(s) to avoid an
            // SSRF via a crafted CDP (e.g. file:// or an internal-service URL).
            foreach (var element in certChain.ChainElements)
            {
                if (element.Certificate.Issuer != element.Certificate.Subject)
                {
                    var cdp = CryptoUtils.CDPFromCertificateExts(element.Certificate.Extensions);

                    if (!IsHttpUrl(cdp))
                        continue;

                    using var client = _httpClientFactory.CreateClient();
                    var crlFile = await client.GetByteArrayAsync(cdp, cancellationToken);
                    if (CryptoUtils.IsCertInCRL(crlFile, element.Certificate))
                        throw new Fido2VerificationException($"Cert {element.Certificate.Subject} found in CRL {cdp}");
                }
            }
        }

        var blobPayload = ((JsonWebToken)validateTokenResult.SecurityToken).EncodedPayload;

        MetadataBLOBPayload blob = JsonSerializer.Deserialize(Base64Url.DecodeFromChars(blobPayload), FidoModelSerializerContext.Default.MetadataBLOBPayload)!;
        blob.JwtAlg = blobAlg;
        return blob;
    }

    private static bool IsHttpUrl(string? url)
    {
        return Uri.TryCreate(url, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }
}
