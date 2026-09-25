using System;
using System.Buffers.Text;
using System.Collections.Generic;
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
public sealed class Fido2MetadataServiceRepository(IHttpClientFactory httpClientFactory, Fido2Configuration? config = null) : IMetadataRepository
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

    /// <summary>
    /// GlobalSign Root R46, self-signed. GlobalSign began issuing under this root (rather than
    /// <see cref="ROOT_CERT"/>, "GlobalSign Root CA - R3") for TLS/EV certificates including
    /// mds.fidoalliance.org's own; the BLOB's x5c chain includes a copy of this cert cross-signed by R3 for
    /// transition compatibility. Because R46 is now itself widely trusted as a root in its own right (it has
    /// been shipped directly in current OS/browser trust stores for several years), a platform's own chain
    /// builder commonly terminates at R46 rather than walking the cross-sign up to R3 -- so both roots must be
    /// accepted, or MDS validation fails on exactly the platforms most likely to already trust the FIDO root.
    /// </summary>
    /// <remarks>
    /// FIDO Alliance's own metadata documentation, <see href="https://fidoalliance.org/metadata/"/> (retrieved
    /// 2026-09-24), names R46 as the current root and links to GlobalSign's published copy at
    /// <see href="https://valid.r46.roots.globalsign.com/"/> (retrieved 2026-09-25), whose "Base64" section is
    /// this same cert verbatim -- the underlying data was diffed byte-for-byte against it, and the line wrap
    /// below matches <see cref="ROOT_CERT"/>'s (64 base64 characters per line, the same as a PEM export).
    /// </remarks>
    private static ReadOnlySpan<byte> ROOT_CERT_R46 =>
        "MIIFWjCCA0KgAwIBAgISEdK7udcjGJ5AXwqdLdDfJWfRMA0GCSqGSIb3DQEBDAUA"u8 +
        "MEYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRwwGgYD"u8 +
        "VQQDExNHbG9iYWxTaWduIFJvb3QgUjQ2MB4XDTE5MDMyMDAwMDAwMFoXDTQ2MDMy"u8 +
        "MDAwMDAwMFowRjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYt"u8 +
        "c2ExHDAaBgNVBAMTE0dsb2JhbFNpZ24gUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEB"u8 +
        "AQUAA4ICDwAwggIKAoICAQCsrHQy6LNl5brtQyYdpokNRbopiLKkHWPd08EsCVeJ"u8 +
        "OaFV6Wc0dwxu5FUdUiXSE2te4R2pt32JMl8Nnp8semNgQB+msLZ4j5lUlghYruQG"u8 +
        "vGIFAha/r6gjA7aUD7xubMLL1aa7DOn2wQL7Id5m3RerdELv8HQvJfTqa1VbkNud"u8 +
        "316HCkD7rRlr+/fKYIje2sGP1q7Vf9Q8g+7XFkyDRTNrJ9CG0Bwta/OrffGFqfUo"u8 +
        "0q3v84RLHIf8E6M6cqJaESvWJ3En7YEtbWaBkoe0G1h6zD8K+kZPTXhc+CtI4wSE"u8 +
        "y132tGqzZfxCnlEmIyDLPRT5ge1lFgBPGmSXZgjPjHvjK8Cd+RTyG/FWaha/LIWF"u8 +
        "zXg4mutCagI0GIMXTpRW+LaCtfOW3T3zvn8gdz57GSNrLNRyc0NXfeD412lPFzYE"u8 +
        "+cCQYDdF3uYM2HSNrpyibXRdQr4G9dlkbgIQrImwTDsHTUB+JMWKmIJ5jqSngiCN"u8 +
        "I/onccnfxkF0oE32kRbcRoxfKWMxWXEM2G/CtjJ9++ZdU6Z+Ffy7dXxd7Pj2Fxzs"u8 +
        "x2sZy/N78CsHpdlseVR2bJ0cpm4O6XkMqCNqo98bMDGfsVR7/mrLZqrcZdCinkqa"u8 +
        "ByFrgY/bxFn63iLABJzjqls2k+g9vXqhnQt2sQvHnf3PmKgGwvgqo6GDoLclcqUC"u8 +
        "4wIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV"u8 +
        "HQ4EFgQUA1yrc4GHqMywptWU4jaWSf8FmSwwDQYJKoZIhvcNAQEMBQADggIBAHx4"u8 +
        "7PYCLLtbfpIrXTncvtgdokIzTfnvpCo7RGkerNlFo048p9gkUbJUHJNOxO97k4Vg"u8 +
        "JuoJSOD1u8fpaNK7ajFxzHmuEajwmf3lH7wvqMxX63bEIaZHU1VNaL8FpO7XJqti"u8 +
        "2kM3S+LGteWygxk6x9PbTZ4IevPuzz5i+6zoYMzRx6Fcg0XERczzF2sUyQQCPtIk"u8 +
        "pnnpHs6i58FZFZ8d4kuaPp92CC1r2LpXFNqD6v6MVenQTqnMdzGxRBF6XLE+0xRF"u8 +
        "FRhiJBPSy03OXIPBNvIQtQ6IbbjhVp+J3pZmOUdkLG5NrmJ7v2B0GbhWrJKsFjLt"u8 +
        "rWhV/pi60zTe9Mlhww6G9kuEYO4Ne7UyWHmRVSyBQ7N0H3qqJZ4d16GLuc1CLgSk"u8 +
        "ZoNNiTW2bKg2SnkheCLQQrzRQDGQob4Ez8pn7fXwgNNgyYMqIgXQBztSvwyeqiv5"u8 +
        "u+YfjyW6hY0XHgL+XVAEV8/+LbzvXMAaq7afJMbfc2hIkCwU9D9SGuTSyxTDYWnP"u8 +
        "4vkYxboznxSjBF25cfe1lNj2M8FawTSLfJvdkzrnE6JwYZ+vj+vYxXX4M2bUdGc6"u8 +
        "N3ec592kD3ZDZopD8p/7DEJ4Y9HiD2971KE9dJeFt0g5QdYg/NA6s/rob8SKunE3"u8 +
        "vouXsXgxT7PntgMTzlSdriVZzH81Xwj3QEUxeCp6"u8;

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

    private sealed record CachedRawBlob(EntityTagHeaderValue ETag, string RawBlob, Uri BlobUri);

    // Set after each successful (non-304) fetch that returns an ETag, and read at the start of the next fetch
    // to conditionally re-validate. Plain field access is fine here: a torn read just means an occasional
    // fetch skips the conditional GET optimization, not a correctness issue.
    private CachedRawBlob? _cachedRawBlob;

    // The highest BLOB serial number seen so far, for rollback protection. Same reasoning as _cachedRawBlob
    // applies: a torn read can only cost us one rejected rollback, and the value never decreases.
    private int _highestBlobNumber;

    public Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
    {
        return Task.FromResult<MetadataStatement?>(entry.MetadataStatement);
    }

    public async Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
    {
        var (rawBLOB, blobUri) = await GetRawBlobAsync(cancellationToken);

        // Fido2Configuration.MdsRootCertificates lets a consumer override the pinned root(s) -- e.g. if FIDO
        // Alliance rotates roots again before this library ships an update, or against a self-hosted/enterprise
        // MDS mirror -- same pattern as AppleWebAuthnRootCertificate/AndroidSafetyNetRootCertificate. Ownership of
        // configured certs stays with the caller, so they are not disposed here.
        if (config?.MdsRootCertificates is { Count: > 0 } configuredRoots)
        {
            return await DeserializeAndValidateBlobAsync(rawBLOB, configuredRoots, cancellationToken, blobUri);
        }

        using var rootCertR3 = X509CertificateHelper.CreateFromBase64String(ROOT_CERT);
        using var rootCertR46 = X509CertificateHelper.CreateFromBase64String(ROOT_CERT_R46);
        return await DeserializeAndValidateBlobAsync(rawBLOB, [rootCertR3, rootCertR46], cancellationToken, blobUri);
    }

    /// <summary>
    /// Downloads the raw BLOB JWT, returning it along with the URI it was actually downloaded from -- which is
    /// the URI after any redirects, and is what an <c>x5u</c> header has to share a web-origin with.
    /// </summary>
    private async Task<(string RawBlob, Uri BlobUri)> GetRawBlobAsync(CancellationToken cancellationToken)
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
                return (cached.RawBlob, cached.BlobUri);
            }

            if (response.IsSuccessStatusCode)
            {
                var rawBlob = await response.Content.ReadAsStringAsync(cancellationToken);
                var blobUri = response.RequestMessage?.RequestUri ?? request.RequestUri!;

                _cachedRawBlob = response.Headers.ETag is { } etag
                    ? new CachedRawBlob(etag, rawBlob, blobUri)
                    : null;

                return (rawBlob, blobUri);
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

    // internal for testing: the trust root(s) are injected so a self-built chain can be validated without the
    // real GlobalSign roots. Production always passes the bundled ROOT_CERT and ROOT_CERT_R46. blobUri is only
    // required when the BLOB header actually names an x5u -- its web-origin is checked against it -- so tests
    // that only exercise x5c can omit it.
    internal async Task<MetadataBLOBPayload> DeserializeAndValidateBlobAsync(string rawBLOBJwt, IReadOnlyList<X509Certificate2> trustedRoots, CancellationToken cancellationToken = default, Uri? blobUri = null)
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


        // MDS 3.1.1 §3.2: prefer x5u, fall back to x5c, and if neither is present the BLOB signing trust
        // anchor is itself considered the signing certificate chain.
        X509Certificate2[] blobCerts;

        if (blobHeader.TryGetProperty("x5u", out var x5uEl))
        {
            if (blobUri is null)
                throw new Fido2MetadataException("The BLOB header named an x5u, but no BLOB URI was supplied to check its web-origin against");

            blobCerts = await GetCertificateChainFromX5uAsync(x5uEl, blobUri, cancellationToken);
        }
        else if (blobHeader.TryGetProperty("x5c", out var x5cEl))
        {
            if (!x5cEl.TryDecodeArrayOfBase64EncodedBytes(out var x5cRawKeys))
            {
                throw new Fido2MetadataException("The x5c value in the BLOB header is malformed");
            }

            if (x5cRawKeys.Length is 0)
            {
                throw new Fido2MetadataException("No x5c keys were present in the BLOB header");
            }

            blobCerts = Array.ConvertAll(x5cRawKeys, static raw => X509CertificateHelper.CreateFromRawData(raw));
        }
        else
        {
            // Neither header names a chain, so per MDS 3.1.1 the BLOB signing trust anchor is itself the
            // signing certificate. MDS 3.1.1 always sends x5c in practice, so this is not exercised by the
            // real service; there is no way to tell which trusted root would have signed it, so the first one
            // is used.
            blobCerts = [trustedRoots[0]];
        }

        var keys = new SecurityKey[blobCerts.Length];

        for (int i = 0; i < blobCerts.Length; i++)
        {
            var cert = blobCerts[i];

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
        certChain.ChainPolicy.ExtraStore.AddRange(trustedRoots.ToArray());
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

        // The BLOB signing chain MUST terminate at one of the bundled FIDO Alliance roots, regardless of the
        // host's trust store. X509Chain's default System trust mode returns true for a chain to ANY
        // publicly-trusted CA, so a successful Build() alone would accept a BLOB signed under an unrelated
        // public CA. Pin the terminal certificate to one of the accepted roots.
        var matchedRoot = certChain.ChainElements.Count > 0
            ? trustedRoots.FirstOrDefault(r => r.Thumbprint.Equals(certChain.ChainElements[^1].Certificate.Thumbprint, StringComparison.Ordinal))
            : null;
        bool pinnedToFidoRoot = matchedRoot is not null;

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
                matchedRoot is not null &&
                // the chain accounts for exactly the certificates the header supplied, plus the root we added --
                // unless the header's chain already ended at that root
                certChain.ChainElements.Count == blobCerts.Length + (matchedRoot.Thumbprint == blobCerts[^1].Thumbprint ? 0 : 1) &&
                // and that the root cert has exactly one status with the value of UntrustedRoot
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
        }

        // MDS 3.1.1 §3.2: "All certificates in the chain MUST be checked for revocation", and the FIDO Server
        // SHOULD ignore the BLOB if one of them is revoked. This runs whether or not the platform's trust store
        // already accepted the chain above -- the BLOB signing root is a public GlobalSign root that most
        // platform trust stores already carry, which makes that the common path, and it must not skip
        // revocation checking. The chain is built with RevocationMode.NoCheck because the CRLs live at the MDS
        // CRL location rather than wherever the platform would look, so this is done explicitly; the CRL
        // distribution point is taken from the certificate, so it is restricted to http(s) to avoid an SSRF via
        // a crafted CDP (e.g. file:// or an internal-service URL).
        await VerifyNoCertificateIsRevokedAsync(certChain, cancellationToken);

        var blobPayload = ((JsonWebToken)validateTokenResult.SecurityToken).EncodedPayload;

        MetadataBLOBPayload blob = JsonSerializer.Deserialize(Base64Url.DecodeFromChars(blobPayload), FidoModelSerializerContext.Default.MetadataBLOBPayload)!;

        EnsureBlobIsNotARollback(blob.Number);

        blob.JwtAlg = blobAlg;
        return blob;
    }

    /// <summary>
    /// Rejects a BLOB whose serial number went backwards, and records the number otherwise.
    /// </summary>
    /// <remarks>
    /// MDS 3.1.1 §3.2: the FIDO Server "SHOULD also ignore the file if its number (no) is less or equal to the
    /// number of the last Metadata BLOB object cached locally". Only a strictly lower number is rejected here.
    /// This repository hands the parsed BLOB back on every call rather than serving one from its own cache, so
    /// re-fetching the current BLOB legitimately produces the same number and rejecting equality would break
    /// the ordinary refresh. A lower number can only be a rollback, and is refused.
    /// </remarks>
    internal void EnsureBlobIsNotARollback(int blobNumber)
    {
        if (blobNumber < _highestBlobNumber)
        {
            throw new Fido2MetadataException(
                $"The MDS BLOB number {blobNumber} is lower than the previously seen number {_highestBlobNumber}, which indicates a rollback");
        }

        _highestBlobNumber = blobNumber;
    }

    /// <summary>
    /// Downloads the BLOB signing certificate chain from the URL in the JWS <c>x5u</c> header.
    /// </summary>
    /// <remarks>
    /// MDS 3.1.1 §3.2 requires the FIDO Server to verify that the x5u URL has the same web-origin as the URL the
    /// BLOB itself was downloaded from, and to ignore the file otherwise, so that a BLOB cannot point at
    /// certificates on an arbitrary site. [JWS] requires the resource to be PEM encoded.
    /// </remarks>
    private async Task<X509Certificate2[]> GetCertificateChainFromX5uAsync(JsonElement x5uEl, Uri blobUri, CancellationToken cancellationToken)
    {
        // Uri.TryCreate accepts a Unix absolute path as a file:// URI, so the scheme has to be checked
        // explicitly rather than inferred from the parse succeeding.
        if (x5uEl.ValueKind is not JsonValueKind.String
            || !Uri.TryCreate(x5uEl.GetString(), UriKind.Absolute, out var x5uUri)
            || x5uUri.Scheme is not (("http") or ("https")))
        {
            throw new Fido2MetadataException("The x5u value in the BLOB header is not an absolute http(s) URL");
        }

        if (!string.Equals(x5uUri.Scheme, blobUri.Scheme, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(x5uUri.Host, blobUri.Host, StringComparison.OrdinalIgnoreCase)
            || x5uUri.Port != blobUri.Port)
        {
            throw new Fido2MetadataException(
                $"The x5u value in the BLOB header has web-origin '{x5uUri.Scheme}://{x5uUri.Authority}', which differs from the BLOB's web-origin '{blobUri.Scheme}://{blobUri.Authority}'");
        }

        using var client = _httpClientFactory.CreateClient();
        var pem = await client.GetStringAsync(x5uUri, cancellationToken);

        var chain = new X509Certificate2Collection();

        try
        {
            chain.ImportFromPem(pem);
        }
        catch (CryptographicException ex)
        {
            throw new Fido2MetadataException($"The certificate chain at the x5u URL '{x5uUri}' could not be parsed", ex);
        }

        if (chain.Count is 0)
        {
            throw new Fido2MetadataException($"No certificates were present at the x5u URL '{x5uUri}'");
        }

        return [.. chain];
    }

    /// <summary>
    /// Checks every non-root certificate in the chain against the CRL its distribution point names.
    /// </summary>
    /// <remarks>
    /// The distribution point is a plain http(s) URL, so whatever it returns proves nothing on its own until
    /// its signature has been verified against the issuing certificate (the next element up the chain) and its
    /// <c>nextUpdate</c> time checked -- otherwise a forged or replayed CRL response could be used to hide a
    /// real revocation. A CRL that fails either check is treated as unusable, the same as one that could not be
    /// fetched at all: see <see cref="CryptoUtils.IsCertInCRL(ReadOnlyMemory{byte}, X509Certificate2, X509Certificate2, DateTimeOffset?)"/>.
    /// </remarks>
    private async Task VerifyNoCertificateIsRevokedAsync(X509Chain certChain, CancellationToken cancellationToken)
    {
        // The last element is the trust anchor: it has no issuer above it, and no CRL of its own covers it.
        for (int i = 0; i < certChain.ChainElements.Count - 1; i++)
        {
            var certificate = certChain.ChainElements[i].Certificate;
            var issuer = certChain.ChainElements[i + 1].Certificate;

            if (!CryptoUtils.TryGetCrlDistributionPointUrl(certificate, out var cdp))
                throw new Fido2VerificationException($"Cert {certificate.Subject} has no CRL distribution point");

            using var client = _httpClientFactory.CreateClient();
            var crlFile = await client.GetByteArrayAsync(cdp, cancellationToken);

            bool isRevoked;
            try
            {
                isRevoked = CryptoUtils.IsCertInCRL(crlFile, certificate, issuer, DateTimeOffset.UtcNow);
            }
            catch (CryptographicException ex)
            {
                throw new Fido2VerificationException($"The CRL at {cdp} could not be used to check {certificate.Subject}: {ex.Message}", ex);
            }

            if (isRevoked)
                throw new Fido2VerificationException($"Cert {certificate.Subject} found in CRL {cdp}");
        }
    }
}
