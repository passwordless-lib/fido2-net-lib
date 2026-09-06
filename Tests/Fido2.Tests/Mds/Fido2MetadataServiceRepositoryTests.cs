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
}
