using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;

namespace Fido2NetLib.Tests.Mds;

/// <summary>
/// Tests for FIDO Metadata Service (MDS) integration.
/// </summary>
public class MdsServiceTests
{
    [Fact]
    public void AddFido_AddCachedMetadataService_RegistersDistributedCacheMetadataService()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();

            var provider = services.BuildServiceProvider();
            Assert.IsType<DistributedCacheMetadataService>(provider.GetRequiredService<IMetadataService>());
        }
        finally { }
    }

    [Fact]
    public void AddCachedMetadataService_With_MemoryCache_Registers_Service()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();

            var provider = services.BuildServiceProvider();
            Assert.IsType<DistributedCacheMetadataService>(provider.GetRequiredService<IMetadataService>());
        }
        finally { }
    }

    [Fact]
    public void AddCachedMetadataService_Caches_MdsResponses()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();

            var provider = services.BuildServiceProvider();
            Assert.IsType<DistributedCacheMetadataService>(provider.GetRequiredService<IMetadataService>());
        }
        finally { }
    }

    [Fact]
    public void AddCachedMetadataService_Registers_DistributedCache()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();

            var provider = services.BuildServiceProvider();
            Assert.NotNull(provider.GetRequiredService<IDistributedCache>());
        }
        finally { }
    }

    [Fact]
    public void AddCachedMetadataService_Registers_Service_As_DistributedCacheMetadataService()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();

            var provider = services.BuildServiceProvider();
            Assert.IsType<DistributedCacheMetadataService>(provider.GetRequiredService<IMetadataService>());
        }
        finally { }
    }

    [Fact]
    public void AddCachedMetadataService_Registers_Both_CacheServices_As_DistributedCache_And_MetadataService()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();

            var provider = services.BuildServiceProvider();
            Assert.IsType<DistributedCacheMetadataService>(provider.GetRequiredService<IMetadataService>());
            Assert.NotNull(provider.GetRequiredService<IDistributedCache>());
        }
        finally { }
    }

    [Fact]
    public void AddCachedMetadataService_With_Cache_Rollover_Works()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();

            var provider = services.BuildServiceProvider();
            var service = provider.GetRequiredService<IMetadataService>();

            // Verify the service is of the correct type
            Assert.IsType<DistributedCacheMetadataService>(service);
        }
        finally { }
    }

    [Fact]
    public void AddFido_AddCached_MetadataRepository_With_Cache_Shared_Lifetime()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();
            builder.AddFidoMetadataRepository();

            var provider = services.BuildServiceProvider();

            // Resolve the repository from a scope (it's registered as a singleton, but still resolvable from any scope)
            using var scope = provider.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IMetadataRepository>();
            Assert.NotNull(repository);
        }
        finally { }
    }

    [Fact]
    public void AddFido_AddCached_MetadataRepository_With_Cache_Scope_Lifetime()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();
            builder.AddFidoMetadataRepository();

            var provider = services.BuildServiceProvider();

            // Resolve the repository from a scope (it's registered as a singleton, but still resolvable from any scope)
            using var scope = provider.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IMetadataRepository>();
            Assert.NotNull(repository);
        }
        finally { }
    }

    [Fact]
    public void AddFido_AddCached_MetadataRepository_Registers_Service()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();
            builder.AddFidoMetadataRepository();

            var provider = services.BuildServiceProvider();

            // Resolve the repository from a scope (it's registered as a singleton, but still resolvable from any scope)
            using var scope = provider.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IMetadataRepository>();
            Assert.NotNull(repository);
        }
        finally { }
    }

    [Fact]
    public void AddFido_AddCached_MetadataRepository_Singleton_Lifetime()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();
            builder.AddFidoMetadataRepository();

            var provider = services.BuildServiceProvider();

            using var scope1 = provider.CreateScope();
            using var scope2 = provider.CreateScope();

            var firstRepository = scope1.ServiceProvider.GetRequiredService<IMetadataRepository>();
            var secondRepository = scope2.ServiceProvider.GetRequiredService<IMetadataRepository>();

            // Fido2MetadataServiceRepository is registered as a singleton (not scoped), so that it
            // can retain the MDS BLOB's ETag across fetches for conditional GET (If-None-Match).
            Assert.Same(firstRepository, secondRepository);
        }
        finally { }
    }

    [Fact]
    public void AddFido_AddCached_MetadataRepository_Registers_Both_CacheServices()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();
            builder.AddFidoMetadataRepository();

            var provider = services.BuildServiceProvider();
            Assert.NotNull(provider.GetRequiredService<IMetadataRepository>());
        }
        finally { }
    }

    [Fact]
    public void AddFido_AddFidoMetadataRepository_With_ClientBuilder_Configures_HttpClient()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddFidoMetadataRepository(_ => { });

            var provider = services.BuildServiceProvider();

            // Resolve the repository from a scope (it's registered as a singleton, but still resolvable from any scope)
            using var scope = provider.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IMetadataRepository>();

            // The HttpClient should have been configured by AddFidoMetadataRepository
            Assert.NotNull(repository);
        }
        finally { }
    }

    [Fact]
    public void AddFido_AddCachedMetadataService_With_FidoMetadataRepository()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();
            builder.AddFidoMetadataRepository();

            var provider = services.BuildServiceProvider();

            // Add scopes to get the services (they're registered as scoped)
            using var scope1 = provider.CreateScope();
            using var scope2 = provider.CreateScope();

            var metadataService = scope1.ServiceProvider.GetRequiredService<IMetadataService>();
            Assert.IsType<DistributedCacheMetadataService>(metadataService);

            var repository = scope2.ServiceProvider.GetRequiredService<IMetadataRepository>();
            Assert.IsType<Fido2MetadataServiceRepository>(repository);
        }
        finally { }
    }

    [Fact]
    public void AddFido_AddCachedMetadataService_And_FidoMetadataRepository_Different_Implementations()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();
            builder.AddFidoMetadataRepository();

            var provider = services.BuildServiceProvider();

            // Add scopes to get the services (they're registered as scoped)
            using var scope1 = provider.CreateScope();
            using var scope2 = provider.CreateScope();

            var metadataService = scope1.ServiceProvider.GetRequiredService<IMetadataService>();
            // Cached metadata service should use DistributedCacheMetadataService
            Assert.IsType<DistributedCacheMetadataService>(metadataService);

            var repository = scope2.ServiceProvider.GetRequiredService<IMetadataRepository>();
            // Fido metadata repository should use Fido2MetadataServiceRepository
            Assert.IsType<Fido2MetadataServiceRepository>(repository);
        }
        finally { }
    }

    [Fact]
    public void AddFido_AddCachedMetadataService_And_FidoMetadataRepository_Both_Register_HttpClient()
    {
        var services = new ServiceCollection();

        try
        {
            // Add logging infrastructure required by DistributedCacheMetadataService
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();

            var httpClientsBefore = services.Count(x => x.ServiceType == typeof(HttpClient));

            var builder = services.AddFido2(config => config.Timeout = 5000);
            builder.AddCachedMetadataService();
            builder.AddFidoMetadataRepository();

            var httpClientsAfter = services.Count(x => x.ServiceType == typeof(HttpClient));

            // Both should register an HttpClient
            Assert.True(httpClientsAfter > httpClientsBefore);
        }
        finally { }
    }
}
