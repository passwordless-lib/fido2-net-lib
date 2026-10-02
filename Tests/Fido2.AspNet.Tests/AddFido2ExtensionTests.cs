using System;
using System.Collections.Generic;
using System.Threading.Tasks;

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
                ["RPName"] = "Test Server",
                ["RPID"] = "localhost",
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
        Assert.Equal("Test Server", config.RPName);
        Assert.Equal("localhost", config.RPID);

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
            config.RPName = "Action Server";
            config.RPID = "example.com";
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
        Assert.Equal("Action Server", config.RPName);
        Assert.Equal("example.com", config.RPID);
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
    public async Task AddFileSystemMetadataRepository_LogsThroughTheRegisteredLoggingWhenThereIsAny()
    {
        // Arrange: no logging registered at all, then logging with a provider we can inspect
        var withoutLogging = new ServiceCollection();
        withoutLogging.AddFido2(config => { }).AddFileSystemMetadataRepository("/tmp/fido2-missing-" + Guid.NewGuid().ToString("N"));

        var provider = new RecordingLoggerProvider();
        var withLogging = new ServiceCollection();
        withLogging.AddLogging(logging => logging.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));
        withLogging.AddFido2(config => { }).AddFileSystemMetadataRepository("/tmp/fido2-missing-" + Guid.NewGuid().ToString("N"));

        // Act
        await withoutLogging.BuildServiceProvider().GetRequiredService<IMetadataRepository>().GetBLOBAsync();
        await withLogging.BuildServiceProvider().GetRequiredService<IMetadataRepository>().GetBLOBAsync();

        // Assert: the repository works without a logger, and reports through one when it is there
        var entry = Assert.Single(provider.Entries);
        Assert.Equal(typeof(FileSystemMetadataRepository).FullName, entry.Category);
        Assert.Equal(1010, entry.EventId.Id);
        Assert.Equal(LogLevel.Warning, entry.Level);
    }

    private sealed class RecordingLoggerProvider : ILoggerProvider
    {
        public sealed record Entry(string Category, LogLevel Level, EventId EventId, string Message);

        public List<Entry> Entries { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Logger(categoryName, Entries);

        public void Dispose() { }

        private sealed class Logger(string category, List<Entry> entries) : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                entries.Add(new Entry(category, logLevel, eventId, formatter(state, exception)));
            }
        }
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
