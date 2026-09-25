using System.Buffers.Text;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Fido2NetLib.Exceptions;

using Microsoft.Extensions.DependencyInjection;

namespace Fido2NetLib.Tests.Mds;

/// <summary>
/// Tests for the MDS v3.1.1 throttling/retry behavior in <see cref="Fido2MetadataServiceRepository"/>.
/// </summary>
public class Fido2MetadataServiceRepositoryTests
{
    private sealed class ScriptedHandler(params HttpResponseMessage[] responses) : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            var response = responses[Math.Min(CallCount, responses.Length - 1)];
            CallCount++;
            return Task.FromResult(response);
        }
    }

    private static IHttpClientFactory BuildFactory(HttpMessageHandler handler)
    {
        var services = new ServiceCollection();
        services.AddHttpClient(nameof(Fido2MetadataServiceRepository), client =>
            {
                client.BaseAddress = new Uri("https://mds3.example.org/");
            })
            .ConfigurePrimaryHttpMessageHandler(() => handler);

        // The repository also creates unnamed clients, to fetch an x5u chain and to fetch CRLs. Route those
        // through the same handler so a test can never reach the real network.
        services.AddHttpClient(string.Empty)
            .ConfigurePrimaryHttpMessageHandler(() => handler);

        return services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();
    }

    [Fact]
    public async Task GetBLOBAsync_DoesNotRetry_OnNonThrottledError()
    {
        var handler = new ScriptedHandler(new HttpResponseMessage(HttpStatusCode.BadRequest));
        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        await Assert.ThrowsAsync<Fido2MetadataException>(() => repository.GetBLOBAsync());

        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task GetBLOBAsync_RetriesOnThrottling_ThenSucceedsReadingBody()
    {
        var throttled = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        throttled.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromMilliseconds(1));

        var success = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("not-a-valid-jwt")
        };

        var handler = new ScriptedHandler(throttled, success);
        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        // The retry succeeds in fetching a body; the body itself isn't a valid JWT, so
        // parsing fails afterward. This confirms the throttled response was retried rather
        // than surfaced as a Fido2MetadataException.
        await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());

        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task GetBLOBAsync_GivesUpAfterMaxRetryAttempts()
    {
        var throttled = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        throttled.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromMilliseconds(1));

        var handler = new ScriptedHandler(throttled);
        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        await Assert.ThrowsAsync<Fido2MetadataException>(() => repository.GetBLOBAsync());

        // 1 initial attempt + 4 retries
        Assert.Equal(5, handler.CallCount);
    }

    [Fact]
    public async Task GetBLOBAsync_RejectsUnsupportedJwsAlgorithm()
    {
        static string Base64UrlEncode(string s) =>
            Base64Url.EncodeToString(Encoding.UTF8.GetBytes(s));

        // "alg": "HS256" (a symmetric algorithm) is not in the asymmetric allow-list; this
        // guards against alg-confusion attacks and must be rejected before any signature or
        // certificate-chain validation is attempted.
        var header = Base64UrlEncode("""{"alg":"HS256","x5c":["AAAA"]}""");
        var payload = Base64UrlEncode("""{}""");
        var jwt = $"{header}.{payload}.signature";

        var success = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt)
        };

        var handler = new ScriptedHandler(success);
        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        var ex = await Assert.ThrowsAsync<Fido2MetadataException>(() => repository.GetBLOBAsync());
        Assert.Contains("alg", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static string Base64UrlEncode(string s) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(s));

    private static HttpResponseMessage BlobWithHeader(string header) => new(HttpStatusCode.OK)
    {
        Content = new StringContent($"{Base64UrlEncode(header)}.{Base64UrlEncode("{}")}.signature")
    };

    [Fact]
    public async Task GetBLOBAsync_RejectsX5uFromAnotherWebOrigin()
    {
        // MDS 3.1.1 §3.2: the x5u URL must share a web-origin with the URL the BLOB was downloaded from, so
        // that a BLOB cannot point the server at certificates on an arbitrary site.
        var handler = new ScriptedHandler(BlobWithHeader("""{"alg":"ES256","x5u":"https://evil.example.com/chain.pem"}"""));
        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        var ex = await Assert.ThrowsAsync<Fido2MetadataException>(() => repository.GetBLOBAsync());

        Assert.Contains("web-origin", ex.Message, StringComparison.Ordinal);

        // The chain was never fetched.
        Assert.Equal(1, handler.CallCount);
    }

    [Theory]
    [InlineData("""{"alg":"ES256","x5u":"/chain.pem"}""")]      // relative
    [InlineData("""{"alg":"ES256","x5u":"not a url"}""")]
    [InlineData("""{"alg":"ES256","x5u":42}""")]
    public async Task GetBLOBAsync_RejectsMalformedX5u(string header)
    {
        var handler = new ScriptedHandler(BlobWithHeader(header));
        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        var ex = await Assert.ThrowsAsync<Fido2MetadataException>(() => repository.GetBLOBAsync());

        Assert.Contains("absolute http(s) URL", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetBLOBAsync_RejectsX5uThatIsNotAPemChain()
    {
        var handler = new ScriptedHandler(
            BlobWithHeader("""{"alg":"ES256","x5u":"https://mds3.example.org/chain.pem"}"""),
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("this is not a PEM file") });

        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        var ex = await Assert.ThrowsAsync<Fido2MetadataException>(() => repository.GetBLOBAsync());

        Assert.Contains("No certificates were present", ex.Message, StringComparison.Ordinal);

        // Same web-origin, so the chain was fetched.
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public void BlobNumberMayNotGoBackwards()
    {
        var repository = new Fido2MetadataServiceRepository(BuildFactory(new ScriptedHandler()));

        repository.EnsureBlobIsNotARollback(42);

        // Re-fetching the current BLOB legitimately reports the same number, and it may go forwards.
        repository.EnsureBlobIsNotARollback(42);
        repository.EnsureBlobIsNotARollback(43);

        var ex = Assert.Throws<Fido2MetadataException>(() => repository.EnsureBlobIsNotARollback(42));

        Assert.Contains("rollback", ex.Message, StringComparison.Ordinal);

        // ...and the highest number seen is unchanged by the rejected BLOB.
        repository.EnsureBlobIsNotARollback(43);
    }

    [Fact]
    public async Task GetBLOBAsync_ReusesCachedBlob_OnNotModified()
    {
        // The BLOB JWT itself doesn't need to validate -- caching happens in GetRawBlobAsync, before
        // DeserializeAndValidateBlobAsync ever runs, so both calls fail the same way regardless.
        var etag = new System.Net.Http.Headers.EntityTagHeaderValue("\"blob-etag\"");

        var fresh = BlobWithHeader("""{"alg":"ES256","x5c":["AAAA"]}""");
        fresh.Headers.ETag = etag;

        var notModified = new HttpResponseMessage(HttpStatusCode.NotModified);

        var handler = new ScriptedHandler(fresh, notModified);
        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        var firstEx = await Assert.ThrowsAnyAsync<Exception>(() => repository.GetBLOBAsync());
        var secondEx = await Assert.ThrowsAnyAsync<Exception>(() => repository.GetBLOBAsync());

        Assert.Equal(2, handler.CallCount);

        // The second request conditionally re-validates using the ETag from the first response...
        Assert.Contains(etag, handler.Requests[1].Headers.IfNoneMatch);

        // ...and gets back the exact same cached raw BLOB, so processing fails identically both times.
        Assert.Equal(firstEx.GetType(), secondEx.GetType());
        Assert.Equal(firstEx.Message, secondEx.Message);
    }

    [Fact]
    public async Task GetBLOBAsync_FetchesCertificateChainFromX5u_WhenPresent()
    {
        using var ecdsaForX5u = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var x5uCertRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=fido2-net-lib-tests",
            ecdsaForX5u,
            System.Security.Cryptography.HashAlgorithmName.SHA256);

        using var cert = x5uCertRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));

        var pem = cert.ExportCertificatePem();

        // Same web-origin (scheme+host+port) as the BaseAddress the BLOB itself was fetched from.
        var handler = new ScriptedHandler(
            BlobWithHeader("""{"alg":"ES256","x5u":"https://mds3.example.org/chain.pem"}"""),
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(pem) });

        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        var ex = await Assert.ThrowsAnyAsync<Exception>(() => repository.GetBLOBAsync());

        // The x5u chain was fetched (2 requests) and parsed without complaint -- whatever fails afterward
        // (the JWT's signature is not real) is not an x5u-specific error.
        Assert.Equal(2, handler.CallCount);
        Assert.DoesNotContain("x5u", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PEM", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("web-origin", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetBLOBAsync_RejectsX5uWithCorruptedPemContent()
    {
        // PEM markers present but the base64 payload between them doesn't decode to a certificate --
        // ImportFromPem throws CryptographicException here, unlike non-PEM text (which it silently
        // treats as containing zero certificates; see GetBLOBAsync_RejectsX5uThatIsNotAPemChain above).
        var handler = new ScriptedHandler(
            BlobWithHeader("""{"alg":"ES256","x5u":"https://mds3.example.org/chain.pem"}"""),
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
            });

        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        var ex = await Assert.ThrowsAsync<Fido2MetadataException>(() => repository.GetBLOBAsync());

        Assert.Contains("could not be parsed", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetBLOBAsync_FallsBackToX5c_WhenX5uAbsent()
    {
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var x5cCertRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=fido2-net-lib-tests",
            ecdsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256);

        using var x5cCert = x5cCertRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        var rawCert = x5cCert.RawData;

        // x5c carries standard (not url-safe) base64.
        var header = $$"""{"alg":"ES256","x5c":["{{Convert.ToBase64String(rawCert)}}"]}""";

        var handler = new ScriptedHandler(BlobWithHeader(header));
        var repository = new Fido2MetadataServiceRepository(BuildFactory(handler));

        var ex = await Assert.ThrowsAnyAsync<Exception>(() => repository.GetBLOBAsync());

        // Only the BLOB itself was fetched -- no x5u chain request was made, confirming the x5c fallback
        // path (rather than the x5u path) was taken.
        Assert.Equal(1, handler.CallCount);
        Assert.DoesNotContain("x5c", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // The BLOB signing chain must terminate at the pinned FIDO Alliance root regardless of the host trust store,
    // and a rejected chain must be refused before any CRL distribution point is contacted. The trust root is
    // injected so a self-built chain can be validated, and this factory throws to prove no network fetch happens.
    private sealed class ThrowingHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => throw new InvalidOperationException("No HTTP request should be made");
    }

    private const string LeafCrlUrl = "http://crl.test/leaf.crl";

    private static (X509Certificate2 root, X509Certificate2 leaf, ECDsa leafKey) BuildChain(bool leafHasCrlDistributionPoint = true)
    {
        // Shared across root and leaf: CertificateRequest.Create rejects a leaf notAfter later than the issuer's,
        // and computing each bound from its own DateTimeOffset.UtcNow call risks the leaf's landing a few
        // milliseconds after the root's on a slow runner.
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(1);

        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Test MDS Root", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var root = rootRequest.CreateSelfSigned(notBefore, notAfter);

        var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=Test MDS Signer", leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        if (leafHasCrlDistributionPoint)
        {
            leafRequest.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([LeafCrlUrl]));
        }
        var leaf = leafRequest.Create(root, notBefore, notAfter, RandomNumberGenerator.GetBytes(8));

        return (root, leaf, leafKey);
    }

    private static byte[] BuildEmptyCrl(X509Certificate2 root)
    {
        var builder = new CertificateRevocationListBuilder();
        return builder.Build(root, crlNumber: 1, DateTimeOffset.UtcNow.AddDays(7), HashAlgorithmName.SHA256);
    }

    // Serves the given CRL bytes for any request, so a chain that pins to the provided root and whose leaf
    // names an HTTP(S) CRL distribution point can be revocation-checked without a real network fetch.
    private sealed class CrlServingHttpClientFactory(byte[] crl) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new StaticContentHandler(crl));

        private sealed class StaticContentHandler(byte[] content) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(content)
                });
            }
        }
    }

    private static string ToBase64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string BuildBlobJwt(X509Certificate2 leaf, ECDsa leafKey, string payloadJson)
    {
        // x5c entries are standard base64 per RFC 7515; the header/payload segments are base64url.
        string header = $"{{\"alg\":\"ES256\",\"x5c\":[\"{Convert.ToBase64String(leaf.RawData)}\"]}}";
        string signingInput = ToBase64Url(Encoding.UTF8.GetBytes(header)) + "." + ToBase64Url(Encoding.UTF8.GetBytes(payloadJson));
        byte[] signature = leafKey.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return signingInput + "." + ToBase64Url(signature);
    }

    private const string ValidBlobPayload = "{\"no\":1,\"nextUpdate\":\"2099-01-01\",\"entries\":[]}";

    [Fact]
    public async Task DeserializeAndValidateBlob_ValidatesWhenChainPinsToProvidedRoot()
    {
        var (root, leaf, leafKey) = BuildChain();
        using (root)
        using (leaf)
        using (leafKey)
        {
            string jwt = BuildBlobJwt(leaf, leafKey, ValidBlobPayload);
            // The leaf names an HTTP CRL distribution point, so a revocation check is required and must succeed
            // against an empty CRL served for it.
            var repository = new Fido2MetadataServiceRepository(new CrlServingHttpClientFactory(BuildEmptyCrl(root)));

            var blob = await repository.DeserializeAndValidateBlobAsync(jwt, [root], CancellationToken.None);

            Assert.Equal(1, blob.Number);
        }
    }

    // Multiple roots can be accepted at once: FIDO Alliance's live MDS BLOB is currently signed under a chain
    // that terminates at GlobalSign Root R46 rather than the legacy GlobalSign Root CA - R3 this library
    // originally pinned to, because R46 is now itself widely trusted as a root in its own right, and a
    // platform's own chain builder commonly terminates there instead of walking a cross-sign up to R3 -- so
    // both have to be accepted. This proves the chain validates against whichever configured root actually
    // matches, not only the first one in the list.
    [Fact]
    public async Task DeserializeAndValidateBlob_ValidatesWhenAnyOfSeveralProvidedRootsMatches()
    {
        var (root, leaf, leafKey) = BuildChain();
        using var decoyRoot = new CertificateRequest("CN=Unrelated Root", ECDsa.Create(ECCurve.NamedCurves.nistP256), HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using (root)
        using (leaf)
        using (leafKey)
        {
            string jwt = BuildBlobJwt(leaf, leafKey, ValidBlobPayload);
            var repository = new Fido2MetadataServiceRepository(new CrlServingHttpClientFactory(BuildEmptyCrl(root)));

            // 'root' is not first, and 'decoyRoot' matches nothing in the chain -- validation must still
            // succeed by finding 'root' among the candidates.
            var blob = await repository.DeserializeAndValidateBlobAsync(jwt, [decoyRoot, root], CancellationToken.None);

            Assert.Equal(1, blob.Number);
        }
    }

    [Fact]
    public async Task DeserializeAndValidateBlob_RejectsWhenChainDoesNotPinToProvidedRoot()
    {
        var (root, leaf, leafKey) = BuildChain();
        var (otherRoot, _, _) = BuildChain();
        using (root)
        using (leaf)
        using (leafKey)
        using (otherRoot)
        {
            string jwt = BuildBlobJwt(leaf, leafKey, ValidBlobPayload);
            var repository = new Fido2MetadataServiceRepository(new ThrowingHttpClientFactory());

            // The JWS signature is valid (signed by the leaf in x5c), but the chain terminates at 'root', not the
            // pinned 'otherRoot'. It must be refused, and refused before any CRL fetch (otherwise the throwing
            // factory would surface an InvalidOperationException instead of this Fido2VerificationException).
            var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
                () => repository.DeserializeAndValidateBlobAsync(jwt, [otherRoot], CancellationToken.None));
            Assert.Equal("Failed to validate cert chain while parsing BLOB", ex.Message);
        }
    }

    // Serves the BLOB JWT for the named ("Fido2MetadataServiceRepository") client GetBLOBAsync fetches it
    // through, and the CRL for the unnamed client the revocation check uses -- lets a test exercise the full
    // GetBLOBAsync() entry point, not just DeserializeAndValidateBlobAsync directly.
    private sealed class BlobAndCrlHttpClientFactory(string jwt, byte[] crl) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            name == nameof(Fido2MetadataServiceRepository)
                ? new HttpClient(new StaticContentHandler(new StringContent(jwt))) { BaseAddress = new Uri("https://mds3.example.org/") }
                : new HttpClient(new StaticContentHandler(new ByteArrayContent(crl)));

        private sealed class StaticContentHandler(HttpContent content) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
            }
        }
    }

    // Fido2Configuration.MdsRootCertificates lets a consumer override the pinned root(s), the same pattern as
    // AppleWebAuthnRootCertificate/AndroidSafetyNetRootCertificate -- default to the hardcoded roots, accept
    // configured ones if set. This exercises the real public entry point (GetBLOBAsync), not the internal
    // DeserializeAndValidateBlobAsync test seam, to prove the constructor/config wiring itself works.
    [Fact]
    public async Task GetBLOBAsync_UsesConfiguredMdsRootCertificates_WhenSet()
    {
        var (root, leaf, leafKey) = BuildChain();
        using (root)
        using (leaf)
        using (leafKey)
        {
            var jwt = BuildBlobJwt(leaf, leafKey, ValidBlobPayload);
            var factory = new BlobAndCrlHttpClientFactory(jwt, BuildEmptyCrl(root));
            var config = new Fido2Configuration { MdsRootCertificates = [root] };
            var repository = new Fido2MetadataServiceRepository(factory, config);

            var blob = await repository.GetBLOBAsync();

            Assert.Equal(1, blob.Number);
        }
    }

    [Fact]
    public async Task GetBLOBAsync_FallsBackToHardcodedRoots_WhenMdsRootCertificatesNotSet()
    {
        var (root, leaf, leafKey) = BuildChain();
        using (root)
        using (leaf)
        using (leafKey)
        {
            var jwt = BuildBlobJwt(leaf, leafKey, ValidBlobPayload);
            var factory = new BlobAndCrlHttpClientFactory(jwt, BuildEmptyCrl(root));
            // MdsRootCertificates left unset: a test-signed BLOB must be rejected against the real hardcoded
            // GlobalSign roots, exactly as if no Fido2Configuration had been supplied at all.
            var repository = new Fido2MetadataServiceRepository(factory, new Fido2Configuration());

            var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => repository.GetBLOBAsync());
            Assert.Equal("Failed to validate cert chain while parsing BLOB", ex.Message);
        }
    }
}
