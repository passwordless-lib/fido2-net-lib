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

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
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
}
