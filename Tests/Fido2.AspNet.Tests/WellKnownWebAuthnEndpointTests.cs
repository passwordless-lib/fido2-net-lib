using System.Text.Json;

using Fido2NetLib;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Fido2.AspNet.Tests;

/// <summary>
/// <see cref="WellKnownWebAuthnEndpointRouteBuilderExtensions.MapFido2WellKnownWebAuthn"/> itself had no test --
/// <see cref="Fido2Configuration.GetWellKnownWebAuthn"/>, the payload it serves, is covered separately in
/// Fido2ConfigurationTests, but nothing verified the route was actually wired up to serve it.
/// </summary>
public class WellKnownWebAuthnEndpointTests
{
    [Fact]
    public async Task MapFido2WellKnownWebAuthn_ServesConfiguredOrigins()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddRouting();
        builder.Services.AddSingleton(new Fido2Configuration
        {
            RPID = "example.org",
            RPName = "example.org",
            // A single origin sidesteps HashSet<string> enumeration order, which this library does not rely on
            // for a single entry; ordering itself is covered separately by Fido2ConfigurationTests.
            Origins = new HashSet<string> { "https://example.org" },
        });

        await using var app = builder.Build();
        app.MapFido2WellKnownWebAuthn();
        await app.StartAsync();

        using var client = app.GetTestClient();
        using var response = await client.GetAsync("/.well-known/webauthn");

        response.EnsureSuccessStatusCode();
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

        var payload = JsonSerializer.Deserialize<WellKnownWebAuthn>(await response.Content.ReadAsStringAsync());

        Assert.NotNull(payload);
        Assert.Equal(["https://example.org"], payload!.Origins);

        await app.StopAsync();
    }
}
