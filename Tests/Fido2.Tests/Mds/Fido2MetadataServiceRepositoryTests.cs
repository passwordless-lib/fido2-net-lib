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

    // The BLOB signing chain must terminate at the pinned FIDO Alliance root regardless of the host trust store,
    // and a rejected chain must be refused before any CRL distribution point is contacted. The trust root is
    // injected so a self-built chain can be validated, and this factory throws to prove no network fetch happens.
    private sealed class ThrowingHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => throw new InvalidOperationException("No HTTP request should be made");
    }

    private static (X509Certificate2 root, X509Certificate2 leaf, ECDsa leafKey) BuildChain()
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Test MDS Root", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=Test MDS Signer", leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        var leaf = leafRequest.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(8));

        return (root, leaf, leafKey);
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
            var repository = new Fido2MetadataServiceRepository(new ThrowingHttpClientFactory());

            var blob = await repository.DeserializeAndValidateBlobAsync(jwt, root, CancellationToken.None);

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
                () => repository.DeserializeAndValidateBlobAsync(jwt, otherRoot, CancellationToken.None));
            Assert.Equal("Failed to validate cert chain while parsing BLOB", ex.Message);
        }
    }
}
