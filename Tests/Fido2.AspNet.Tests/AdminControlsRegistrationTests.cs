using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;

namespace Fido2.AspNet.Tests;

/// <summary>
/// Covers how the admin controls reach an application through Fido2.AspNet: settings binding, the logger reaching
/// <see cref="Fido2"/>, <c>AddAuthenticatorDisplayMetadata()</c> and <c>AddFido2MetadataHealthCheck()</c>.
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
            ["DisplayMetadata:UseConvenienceMetadataService"] = "true",
            ["DisplayMetadata:ConvenienceMetadataServiceUrl"] = "https://mirror.example.test/c-mds",
            ["DisplayMetadata:LocalFilePath"] = "aaguids.json",
            ["DisplayMetadata:RefreshInterval"] = "02:00:00",
        }).Build();

        var services = new ServiceCollection();
        services.AddFido2(configuration);
        var config = services.BuildServiceProvider().GetRequiredService<Fido2Configuration>();

        Assert.Equal([Guid.Parse(DeniedAaguid)], config.AaguidDenyList);
        Assert.Equal([Guid.Parse(AllowedAaguid)], config.AaguidAllowList);
        Assert.False(config.AaguidAllowListRequiresAttestation);
        Assert.Equal(MetadataConsistencyStrictness.Strict, config.MetadataConsistencyStrictness);
        Assert.True(config.RecheckMetadataStatusOnAssertion);
        Assert.True(config.DisplayMetadata.UseConvenienceMetadataService);
        Assert.Equal(new Uri("https://mirror.example.test/c-mds"), config.DisplayMetadata.ConvenienceMetadataServiceUrl);
        Assert.Equal("aaguids.json", config.DisplayMetadata.LocalFilePath);
        Assert.Equal(TimeSpan.FromHours(2), config.DisplayMetadata.RefreshInterval);
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

    [Fact]
    public async Task DisplayMetadataWithNothingConfiguredAnswersNothingAsync()
    {
        var services = new ServiceCollection();
        services.AddFido2(config => config.DisplayMetadata = null).AddAuthenticatorDisplayMetadata();

        var service = Assert.IsType<CompositeAuthenticatorDisplayMetadataService>(services.BuildServiceProvider().GetRequiredService<IAuthenticatorDisplayMetadataService>());

        Assert.Empty(service.Sources);
        Assert.Null(await service.GetDisplayInfoAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task DisplayMetadataPutsTheLocalFileBeforeTheConvenienceServiceAsync()
    {
        var aaguid = Guid.NewGuid();
        var path = Path.GetTempFileName();
        await File.WriteAllTextAsync(path, $$"""{ "{{aaguid}}": { "name": "Local Name" } }""");

        try
        {
            var handler = new StubHandler($$"""{ "no": 1, "{{aaguid}}": { "friendlyNames": { "en-US": "Remote Name" }, "icon": "data:image/png;base64,AAAA" } }""");
            var services = new ServiceCollection();
            services.AddFido2(config =>
            {
                config.DisplayMetadata.LocalFilePath = path;
                config.DisplayMetadata.UseConvenienceMetadataService = true;
            })
            .AddAuthenticatorDisplayMetadata(client => client.ConfigurePrimaryHttpMessageHandler(() => handler));

            var service = Assert.IsType<CompositeAuthenticatorDisplayMetadataService>(services.BuildServiceProvider().GetRequiredService<IAuthenticatorDisplayMetadataService>());
            var info = await service.GetDisplayInfoAsync(aaguid);

            Assert.Collection(service.Sources,
                s => Assert.IsType<FileSystemDisplayMetadataRepository>(s),
                s => Assert.IsType<ConvenienceMetadataService>(s));
            Assert.Equal("Local Name", info?.Name);
            Assert.Equal("data:image/png;base64,AAAA", info?.IconLight);
            Assert.Equal(DisplayMetadataOptions.DefaultConvenienceMetadataServiceUrl, handler.LastRequest);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task TheHealthCheckIsRegisteredWithItsNameTagsAndGracePeriodAsync()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddFido2(config => { })
            .AddMetadataService<NoMetadataService>()
            .AddFido2MetadataHealthCheck("mds", TimeSpan.FromHours(3), ["ready"]);

        var provider = services.BuildServiceProvider();
        var registration = Assert.Single(provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>().Value.Registrations);
        var check = Assert.IsType<Fido2MetadataHealthCheck>(registration.Factory(provider));

        Assert.Equal("mds", registration.Name);
        Assert.Contains("ready", registration.Tags);
        Assert.Equal(TimeSpan.FromHours(3), check.StaleGracePeriod);
        Assert.Equal(HealthStatus.Healthy, (await provider.GetRequiredService<HealthCheckService>().CheckHealthAsync()).Status);
    }

    [Fact]
    public void TheHealthCheckDefaultsItsNameAndGracePeriod()
    {
        var services = new ServiceCollection();
        services.AddFido2(config => { }).AddMetadataService<NoMetadataService>().AddFido2MetadataHealthCheck();

        var provider = services.BuildServiceProvider();
        var registration = Assert.Single(provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>().Value.Registrations);

        Assert.Equal("fido2-metadata", registration.Name);
        Assert.Equal(Fido2MetadataHealthCheck.DefaultStaleGracePeriod, Assert.IsType<Fido2MetadataHealthCheck>(registration.Factory(provider)).StaleGracePeriod);
    }

    [Fact]
    public void TheRegistrationMethodsRejectANullBuilder()
    {
        Assert.Throws<ArgumentNullException>(() => ((IFido2NetLibBuilder)null).AddAuthenticatorDisplayMetadata());
        Assert.Throws<ArgumentNullException>(() => ((IFido2NetLibBuilder)null).AddFido2MetadataHealthCheck());
    }

    private sealed class NoMetadataService : IMetadataService
    {
        public bool ConformanceTesting() => false;

        public Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaGuid, CancellationToken cancellationToken = default) => Task.FromResult<MetadataBLOBPayloadEntry>(null);
    }

    private sealed class StubHandler(string content) : HttpMessageHandler
    {
        public Uri LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(content) });
        }
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
