using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Fido2NetLib;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Test
{
    public class MetadataServiceTests
    {

        [Fact]
        public async Task ConformanceTestClient()
        {
            var client = new ConformanceMetadataRepository(null, "http://localhost");

            var toc = await client.GetToc();

            Assert.True(toc.Entries.Length > 0);

            var entry_1 = await client.GetMetadataStatement(toc, toc.Entries[toc.Entries.Length - 1]);

            Assert.NotNull(entry_1.Description);

        }

        [Fact]
        public async Task DistributedCacheMetadataService_Works()
        {
            var services = new ServiceCollection();

            var staticClient = new StaticMetadataRepository(DateTime.UtcNow.AddDays(5));

            var clients = new List<IMetadataRepository>();

            clients.Add(staticClient);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataService(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataService>>());

            await service.Initialize();

            var entry = service.GetEntry(Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"));

            Assert.True(entry.MetadataStatement.Description == "Yubico Security Key NFC");

            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataService:StaticMetadataRepository:Entry:6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

            Assert.NotNull(cacheEntry);
        }

        [Fact]
        public async Task DistributedCacheMetadataService_CacheSuppressionWorks()
        {
            var services = new ServiceCollection();

            var staticClient = new StaticMetadataRepository(null);

            var clients = new List<IMetadataRepository>();

            clients.Add(staticClient);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataService(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataService>>());

            await service.Initialize();

            var entry = service.GetEntry(Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"));

            Assert.True(entry.MetadataStatement.Description == "Yubico Security Key NFC");

            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataService:StaticMetadataRepository:Entry:6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

            Assert.Null(cacheEntry);
        }
    }
}
