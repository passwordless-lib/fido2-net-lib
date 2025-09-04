using System;

using Fido2NetLib;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Fido2.AspNet.Tests;

public class AddFido2ExtensionTests
{
    [Fact]
    public void AddFido2_WithConfiguration_RegistersServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["ServerName"] = "Test Server",
                ["ServerDomain"] = "localhost",
                ["Origins"] = "https://localhost:5001"
            })
            .Build();

        // Act
        var builder = services.AddFido2(configuration);

        // Assert
        Assert.NotNull(builder);
        Assert.IsAssignableFrom<IFido2NetLibBuilder>(builder);

        var serviceProvider = services.BuildServiceProvider();

        // Verify IFido2 can be resolved
        var fido2 = serviceProvider.GetService<IFido2>();
        Assert.NotNull(fido2);

        // Verify Fido2Configuration can be resolved
        var config = serviceProvider.GetService<Fido2Configuration>();
        Assert.NotNull(config);
        Assert.Equal("Test Server", config.ServerName);
        Assert.Equal("localhost", config.ServerDomain);

        // Verify ISystemClock is registered
        var systemClock = serviceProvider.GetService<ISystemClock>();
        Assert.NotNull(systemClock);
        
        // Verify MDS is null
        // var mds = serviceProvider.GetService<IMetadataService>();
        // Assert.Null(mds);
    }

    [Fact]
    public void AddFido2_WithSetupAction_RegistersServices()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        var builder = services.AddFido2(config =>
        {
            config.ServerName = "Action Server";
            config.ServerDomain = "example.com";
            config.Origins = new HashSet<string> { "https://example.com" };
        });

        // Assert
        Assert.NotNull(builder);
        Assert.IsAssignableFrom<IFido2NetLibBuilder>(builder);

        var serviceProvider = services.BuildServiceProvider();

        // Verify IFido2 can be resolved
        var fido2 = serviceProvider.GetService<IFido2>();
        Assert.NotNull(fido2);

        // Verify Fido2Configuration can be resolved with correct values
        var config = serviceProvider.GetService<Fido2Configuration>();
        Assert.NotNull(config);
        Assert.Equal("Action Server", config.ServerName);
        Assert.Equal("example.com", config.ServerDomain);
        Assert.Contains("https://example.com", config.Origins);

        // Verify ISystemClock is registered
        var systemClock = serviceProvider.GetService<ISystemClock>();
        Assert.NotNull(systemClock);
        
        // Verify MDS is null
        // var mds = serviceProvider.GetService<IMetadataService>();
        // Assert.Null(mds);
    }

    [Fact]
    public void AddMetadataService_RegistersCustomMetadataService()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = services.AddFido2(config => { });

        // Act
        builder.AddMetadataService<TestMetadataService>();

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var metadataService = serviceProvider.GetService<IMetadataService>();
        Assert.NotNull(metadataService);
        Assert.IsType<TestMetadataService>(metadataService);
    }

    [Fact]
    public void AddCachedMetadataService_RegistersCachedService()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMemoryCache();
        services.AddSingleton<IDistributedCache, MemoryDistributedCache>();
        var builder = services.AddFido2(config => { });

        // Act
        builder.AddCachedMetadataService();

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var metadataService = serviceProvider.GetService<IMetadataService>();
        Assert.NotNull(metadataService);
        Assert.IsType<DistributedCacheMetadataService>(metadataService);
    }

    [Fact]
    public void AddMetadataRepository_RegistersCustomMetadataRepository()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = services.AddFido2(config => { });

        // Act
        builder.AddMetadataRepository<TestMetadataRepository>();

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var metadataRepository = serviceProvider.GetService<IMetadataRepository>();
        Assert.NotNull(metadataRepository);
        Assert.IsType<TestMetadataRepository>(metadataRepository);
    }

    [Fact]
    public void AddFileSystemMetadataRepository_RegistersFileSystemRepository()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = services.AddFido2(config => { });
        var testPath = "/tmp/test";

        // Act
        builder.AddFileSystemMetadataRepository(testPath);

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var metadataRepository = serviceProvider.GetService<IMetadataRepository>();
        Assert.NotNull(metadataRepository);
        Assert.IsType<FileSystemMetadataRepository>(metadataRepository);
    }

    [Fact]
    public void AddConformanceMetadataRepository_RegistersConformanceRepository()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = services.AddFido2(config => { });

        // Act
        builder.AddConformanceMetadataRepository();

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var metadataRepository = serviceProvider.GetService<IMetadataRepository>();
        Assert.NotNull(metadataRepository);
        Assert.IsType<ConformanceMetadataRepository>(metadataRepository);
    }

    [Fact]
    public void AddFidoMetadataRepository_RegistersFidoRepository()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = services.AddFido2(config => { });

        // Act
        builder.AddFidoMetadataRepository();

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var metadataRepository = serviceProvider.GetService<IMetadataRepository>();
        Assert.NotNull(metadataRepository);
        Assert.IsType<Fido2MetadataServiceRepository>(metadataRepository);
    }

    [Fact]
    public void Fido2NetLibBuilder_Constructor_ThrowsWhenServicesNull()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new Fido2NetLibBuilder(null));
    }

    [Fact]
    public void Fido2NetLibBuilder_ServicesProperty_ReturnsServices()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        var builder = new Fido2NetLibBuilder(services);

        // Assert
        Assert.Same(services, builder.Services);
    }
}

public class TestMetadataService : IMetadataService
{
    public bool ConformanceTesting() => false;
    public Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default) => Task.FromResult<MetadataBLOBPayloadEntry>(null);
}

public class TestMetadataRepository : IMetadataRepository
{
    public Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default) => Task.FromResult<MetadataBLOBPayload>(null);
    public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default) => Task.FromResult<MetadataStatement>(null);
}
