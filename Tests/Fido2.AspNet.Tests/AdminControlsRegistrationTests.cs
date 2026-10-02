using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Fido2.AspNet.Tests;

/// <summary>
/// Covers how the admin controls reach an application through Fido2.AspNet: settings binding and the logger
/// reaching <see cref="Fido2"/>.
/// </summary>
public class AdminControlsRegistrationTests
{
    private const string DeniedAaguid = "cb69481e-8ff7-4039-93ec-0a2729a154a8";
    private const string AllowedAaguid = "ee882879-721c-4913-9775-3dfcce97072a";

    [Fact]
    public void TheAdminControlsBindFromSettings()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string>
        {
            ["RPID"] = "localhost",
            ["AaguidDenyList:0"] = DeniedAaguid,
            ["AaguidAllowList:0"] = AllowedAaguid,
            ["AaguidAllowListRequiresAttestation"] = "false",
            ["MetadataConsistencyStrictness"] = "strict",
            ["RecheckMetadataStatusOnAssertion"] = "true",
        }).Build();

        var services = new ServiceCollection();
        services.AddFido2(configuration);
        var config = services.BuildServiceProvider().GetRequiredService<Fido2Configuration>();

        Assert.Equal([Guid.Parse(DeniedAaguid)], config.AaguidDenyList);
        Assert.Equal([Guid.Parse(AllowedAaguid)], config.AaguidAllowList);
        Assert.False(config.AaguidAllowListRequiresAttestation);
        Assert.Equal(MetadataConsistencyStrictness.Strict, config.MetadataConsistencyStrictness);
        Assert.True(config.RecheckMetadataStatusOnAssertion);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheRegisteredLoggerReachesFido2WithOrWithoutAMetadataServiceAsync(bool withMetadataService)
    {
        var provider = new RecordingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(provider));
        var builder = services.AddFido2(config => { config.RPID = "localhost"; config.Origins = new HashSet<string> { "https://localhost" }; });
        if (withMetadataService)
            builder.AddMetadataService<NoMetadataService>();

        using var scope = services.BuildServiceProvider().CreateScope();
        var fido2 = scope.ServiceProvider.GetRequiredService<IFido2>();

        await Assert.ThrowsAnyAsync<Exception>(() => fido2.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = new AuthenticatorAssertionRawResponse(),
            OriginalOptions = new AssertionOptions(),
            StoredPublicKey = [],
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = (_, _) => Task.FromResult(true)
        }));

        var entry = Assert.Single(provider.Entries);
        Assert.Equal(typeof(Fido2NetLib.Fido2).FullName, entry.Category);
        Assert.Equal(1203, entry.EventId.Id);
    }

    [Fact]
    public void Fido2WorksWithoutAnyLoggingRegistered()
    {
        var services = new ServiceCollection();
        services.AddFido2(config => config.RPID = "localhost");

        var fido2 = services.BuildServiceProvider().CreateScope().ServiceProvider.GetRequiredService<IFido2>();

        Assert.IsType<Fido2NetLib.Fido2>(fido2);
        Assert.NotNull(fido2.GetUnknownCredentialOptions([1]));
    }

    private sealed class NoMetadataService : IMetadataService
    {
        public bool ConformanceTesting() => false;

        public Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaGuid, CancellationToken cancellationToken = default) => Task.FromResult<MetadataBLOBPayloadEntry>(null);
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
                lock (entries)
                    entries.Add(new Entry(category, logLevel, eventId, formatter(state, exception)));
            }
        }
    }
}
