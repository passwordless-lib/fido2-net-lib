using System;
using System.Collections.Generic;
using System.Threading;
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

            var cancellationToken = CancellationToken.None;
            
            var blob = await client.GetBLOBAsync(cancellationToken);
            
            Assert.True(blob.Entries.Length > 0);

            var entry_1 = await client.GetMetadataStatementAsync(blob, blob.Entries[^1], cancellationToken);

            Assert.NotNull(entry_1.Description);
        }

        [Fact]
        public async Task DistributedCacheMetadataService_Works()
        {
            var services = new ServiceCollection();

            var staticClient = new Fido2MetadataServiceRepository(null);

            var clients = new List<IMetadataRepository>();

            clients.Add(staticClient);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            IMetadataService service = new DistributedCacheMetadataService(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataService>>());

            await service.InitializeAsync();

            var entry = await service.GetEntryAsync(Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"));

            Assert.True(entry.MetadataStatement.Description == "Security Key by Yubico with NFC");

            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataService:Fido2MetadataServiceRepository:Entry:6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

            Assert.NotNull(cacheEntry);
        }
    }
}
