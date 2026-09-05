using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Fido2NetLib;
using Fido2NetLib.Exceptions;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;

namespace Test;

public class MetadataServiceTests
{
    private sealed class StubHttpMessageHandler(IReadOnlyList<HttpResponseMessage> responses) : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = responses[Math.Min(CallCount, responses.Count - 1)];
            CallCount++;
            return Task.FromResult(response);
        }
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler) { BaseAddress = new Uri("https://mds.example.test") };
    }

    private static HttpResponseMessage ThrottledResponse(TimeSpan retryAfter)
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(retryAfter);
        return response;
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Retries_On_429_Then_Succeeds()
    {
        var handler = new StubHttpMessageHandler(
        [
            ThrottledResponse(TimeSpan.FromMilliseconds(10)),
            ThrottledResponse(TimeSpan.FromMilliseconds(10)),
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("not-a-valid-jwt") }
        ]);

        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(handler));

        // GetRawBlobAsync succeeds after retrying the two 429 responses; the returned content then
        // fails JWT parsing (expected, since it's not a real BLOB), which proves the raw fetch itself
        // used the third (successful) response rather than one of the throttled ones.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());

        Assert.Contains("3 expected components", ex.Message);
        Assert.Equal(3, handler.CallCount);
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Throws_After_Exhausting_Retries_On_Persistent_429()
    {
        var handler = new StubHttpMessageHandler(
        [
            ThrottledResponse(TimeSpan.FromMilliseconds(10))
        ]);

        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(handler));

        var ex = await Assert.ThrowsAsync<Fido2MetadataException>(() => repository.GetBLOBAsync());

        Assert.Contains("429", ex.Message);
        // initial attempt + 4 retries (MaxRetryAttempts) = 5 total requests
        Assert.Equal(5, handler.CallCount);
    }

    private sealed class ETagAwareHttpMessageHandler : HttpMessageHandler
    {
        private const string ETag = "\"blob-etag-v1\"";
        private const string Body = "not-a-valid-jwt";

        public int CallCount { get; private set; }

        public EntityTagHeaderValue LastIfNoneMatch { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            LastIfNoneMatch = request.Headers.IfNoneMatch.FirstOrDefault();

            if (LastIfNoneMatch is not null && LastIfNoneMatch.Tag == ETag)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotModified));
            }

            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Body) };
            response.Headers.ETag = new EntityTagHeaderValue(ETag);
            return Task.FromResult(response);
        }
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Sends_Conditional_Get_Using_Previous_ETag()
    {
        var handler = new ETagAwareHttpMessageHandler();
        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(handler));

        // First fetch: no cached ETag yet, so no If-None-Match is sent; server returns 200 + ETag.
        var firstEx = await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());
        Assert.Contains("3 expected components", firstEx.Message);
        Assert.Null(handler.LastIfNoneMatch);

        // Second fetch: the repository (a singleton in production) reuses the ETag from the first
        // response, the server replies 304, and the repository falls back to its cached raw BLOB
        // content -- proven by getting the same downstream JWT-parsing error rather than one about
        // empty/missing content (a 304 response has no body).
        var secondEx = await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());
        Assert.Contains("3 expected components", secondEx.Message);
        Assert.NotNull(handler.LastIfNoneMatch);
        Assert.Equal("\"blob-etag-v1\"", handler.LastIfNoneMatch.Tag);

        Assert.Equal(2, handler.CallCount);
    }

    private sealed class NoETagHttpMessageHandler : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        public bool AnyRequestSentIfNoneMatch { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            AnyRequestSentIfNoneMatch |= request.Headers.IfNoneMatch.Any();

            // Deliberately never returns an ETag, e.g. a server/proxy that doesn't support conditional GET.
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("not-a-valid-jwt") });
        }
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Does_Not_Send_Conditional_Get_Without_A_Prior_ETag()
    {
        var handler = new NoETagHttpMessageHandler();
        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(handler));

        await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());
        await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());

        Assert.Equal(2, handler.CallCount);
        Assert.False(handler.AnyRequestSentIfNoneMatch);
    }

    [Fact]
    public async Task ConformanceTestClient()
    {
        var client = new ConformanceMetadataRepository(null, "http://localhost:80");

        var cancellationToken = CancellationToken.None;

        var blob = await client.GetBLOBAsync(cancellationToken);

        Assert.NotEmpty(blob.Entries);

        var entry_1 = await client.GetMetadataStatementAsync(blob, blob.Entries[^1], cancellationToken);

        Assert.NotNull(entry_1.Description);
    }

    public class MockRepository : IMetadataRepository
    {
        public int GetBLOBAsyncCount { get; private set; }

        private string _nextUpdate;
        private int _number;

        public string NextUpdate
        {
            set
            {
                _nextUpdate = value;
                _number++;
            }
            get
            {
                return _nextUpdate;
            }
        }

        public MockRepository(string nextUpdate)
        {
            _nextUpdate = nextUpdate;
            _number = 1;
        }

        public Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            GetBLOBAsyncCount++;

            var payload = new MetadataBLOBPayload
            {
                NextUpdate = NextUpdate,
                Number = _number,
                Entries =
                [
                    new MetadataBLOBPayloadEntry
                    {
                        AaGuid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"),
                        MetadataStatement = new MetadataStatement
                        {
                            Description = "Security Key by Yubico with NFC"
                        }
                    }
                ]
            };

            return Task.FromResult(payload);

        }

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(entry.MetadataStatement);
        }
    }

    public class MockClock(DateTimeOffset time) : ISystemClock
    {
        public DateTimeOffset UtcNow { get; set; } = time;
    }

    private sealed class U2FStyleMockRepository(string attestationCertificateKeyIdentifier) : IMetadataRepository
    {
        public Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            var payload = new MetadataBLOBPayload
            {
                NextUpdate = "2099-01-01",
                Number = 1,
                Entries =
                [
                    new MetadataBLOBPayloadEntry
                    {
                        // FIDO U2F authenticators have neither an AAID nor an AAGUID in MDS; they're
                        // identified solely by the attestation certificate's key identifier.
                        AaGuid = null,
                        AttestationCertificateKeyIdentifiers = [attestationCertificateKeyIdentifier],
                        MetadataStatement = new MetadataStatement
                        {
                            Description = "U2F Security Key"
                        }
                    }
                ]
            };

            return Task.FromResult(payload);
        }

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(entry.MetadataStatement);
        }
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Falls_Back_To_Attestation_Certificate_Key_Identifier()
    {
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=Test U2F Attestation Cert", ecdsa, System.Security.Cryptography.HashAlgorithmName.SHA256);
        using var attestationCertificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var keyIdentifier = MetadataBLOBPayloadEntry.ComputeAttestationCertificateKeyIdentifier(attestationCertificate);

        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddLogging();

        var provider = services.BuildServiceProvider();

        var repositories = new List<IMetadataRepository> { new U2FStyleMockRepository(keyIdentifier) };

        var service = new DistributedCacheMetadataService(
            repositories,
            provider.GetService<IDistributedCache>(),
            provider.GetService<IMemoryCache>(),
            provider.GetService<ILogger<DistributedCacheMetadataService>>(),
            new MockClock(DateTimeOffset.UtcNow)
        );

        // An AAGUID-only lookup finds nothing, since this entry has no AAGUID.
        var noMatch = await service.GetEntryAsync(Guid.NewGuid());
        Assert.Null(noMatch);

        // But passing the attestation trust path lets it match via AttestationCertificateKeyIdentifiers.
        var match = await service.GetEntryAsync(Guid.NewGuid(), [attestationCertificate]);

        Assert.NotNull(match);
        Assert.Equal("U2F Security Key", match.MetadataStatement.Description);
    }

    [Fact]
    public async Task DistributeCacheMetadataService_Cache_Rollover_Works()
    {
        var nextUpdateTime = DateTimeOffset.Parse("2021-12-01T00:00:00Z");
        var currentTime = DateTimeOffset.Parse("2021-11-30T00:00:00Z");

        var services = new ServiceCollection();

        var staticClient = new MockRepository(nextUpdateTime.ToString("yyyy-MM-dd"));

        var repositories = new List<IMetadataRepository>();

        var currentTimeClock = new MockClock(currentTime);

        repositories.Add(staticClient);

        services.AddDistributedMemoryCache(options =>
        {
            options.Clock = currentTimeClock;
        });
        services.AddMemoryCache(options =>
        {
            options.Clock = currentTimeClock;
        });
        services.AddLogging();

        var provider = services.BuildServiceProvider();

        var distributedCache = provider.GetService<IDistributedCache>();
        var memCache = provider.GetService<IMemoryCache>();

        var serviceInstance1 = new DistributedCacheMetadataService(
            repositories,
            distributedCache,
            memCache,
            provider.GetService<ILogger<DistributedCacheMetadataService>>(),
            currentTimeClock
        );

        var entryIdGuid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

        var entry = await serviceInstance1.GetEntryAsync(entryIdGuid);

        for (int x = 0; x < 10; x++)
        {
            await serviceInstance1.GetEntryAsync(entryIdGuid);
        }

        Assert.Equal(1, staticClient.GetBLOBAsyncCount);

        Assert.Equal("Security Key by Yubico with NFC", entry.MetadataStatement.Description);

        var blobEntry = await distributedCache.GetStringAsync("DistributedCacheMetadataService:V2:" + staticClient.GetType().Name + ":TOC");

        var itemEntry = memCache.Get<MetadataBLOBPayloadEntry>($"DistributedCacheMetadataService:V2:{entryIdGuid}");

        Assert.NotNull(blobEntry);

        Assert.Equal(itemEntry.AaGuid, entryIdGuid);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-11-30 23:59:59.999Z"); //Before next update

        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(1, staticClient.GetBLOBAsyncCount);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-12-01 23:59:59.999Z"); //Before buffer period (24 hours)

        await serviceInstance1.GetEntryAsync(entryIdGuid);
        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(1, staticClient.GetBLOBAsyncCount);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-12-02 00:00:00.001Z"); //After buffer period (24 hours)

        staticClient.NextUpdate = "2021-12-30";

        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(2, staticClient.GetBLOBAsyncCount);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-12-29 01:00:00.001Z");

        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(2, staticClient.GetBLOBAsyncCount);
    }
}
