using Fido2NetLib;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;

namespace Test;

public class MetadataServiceTests
{
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
                Entries = new MetadataBLOBPayloadEntry[]
            {
                new MetadataBLOBPayloadEntry
                {
                    AaGuid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"),
                    MetadataStatement = new MetadataStatement
                    {
                        Description = "Security Key by Yubico with NFC"
                    }
                }
            }
            };

            return Task.FromResult(payload);

        }

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(entry.MetadataStatement);
        }
    }

    public class MockClock : ISystemClock
    {
        public MockClock(DateTimeOffset time)
        {
            UtcNow = time;
        }

        public DateTimeOffset UtcNow { get; set; }
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

        Assert.True(entry.MetadataStatement.Description == "Security Key by Yubico with NFC");

        var blobEntry = await distributedCache.GetStringAsync("DistributedCacheMetadataService:V2:" + staticClient.GetType().Name + ":TOC");

        var itemEntry = memCache.Get<MetadataBLOBPayloadEntry>($"DistributedCacheMetadataService:V2:{entryIdGuid}");

        Assert.NotNull(blobEntry);

        Assert.Equal(itemEntry.AaGuid, entryIdGuid);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-11-30 23:59:59.999Z"); //Before next update

        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(1, staticClient.GetBLOBAsyncCount);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-12-02 00:59:59.999Z"); //Before buffer period (25 hours)

        await serviceInstance1.GetEntryAsync(entryIdGuid);
        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(1, staticClient.GetBLOBAsyncCount);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-12-02 01:00:00.001Z"); //After buffer period (25 hours)

        staticClient.NextUpdate = "2021-12-30";

        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(2, staticClient.GetBLOBAsyncCount);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-12-29 01:00:00.001Z");

        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(2, staticClient.GetBLOBAsyncCount);
    }
}
