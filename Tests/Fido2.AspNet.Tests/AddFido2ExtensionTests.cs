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
}
