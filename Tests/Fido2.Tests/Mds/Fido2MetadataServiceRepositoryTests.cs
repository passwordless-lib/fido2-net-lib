using System.Buffers.Text;
using System.Net;
using System.Net.Http;
using System.Text;

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
}
