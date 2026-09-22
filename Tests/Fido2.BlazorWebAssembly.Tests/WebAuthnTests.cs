using Fido2.BlazorWebAssembly;

using Fido2NetLib;
using Fido2NetLib.Objects;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;

namespace Test;

public class WebAuthnTests
{
    private const string ModulePath = "./_content/Fido2.BlazorWebAssembly/js/WebAuthn.js";

    /// <summary>
    /// Stands in for the browser: records every call, hands out one module object, and can be told to refuse the
    /// import, as a WebView does before it is ready or a server does before the circuit is up.
    /// </summary>
    private sealed class FakeJSRuntime : IJSRuntime
    {
        public List<(string Identifier, object?[]? Args)> Calls { get; } = [];
        public FakeModule Module { get; } = new();
        public Exception? ImportFailure { get; set; }

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args) => InvokeAsync<TValue>(identifier, CancellationToken.None, args);

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
        {
            Calls.Add((identifier, args));

            if (identifier != "import")
                throw new InvalidOperationException($"Only the module import goes through the runtime; got {identifier}");

            if (ImportFailure is not null)
                throw ImportFailure;

            return new ValueTask<TValue>((TValue)(object)Module);
        }
    }

    private sealed class FakeModule : IJSObjectReference
    {
        public List<(string Identifier, object?[]? Args)> Calls { get; } = [];
        public Dictionary<string, object> Results { get; } = new();
        public bool Disposed { get; private set; }
        public Exception? DisposeFailure { get; set; }

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args) => InvokeAsync<TValue>(identifier, CancellationToken.None, args);

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
        {
            Calls.Add((identifier, args));
            return new ValueTask<TValue>((TValue)Results[identifier]);
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;

            return DisposeFailure is null ? ValueTask.CompletedTask : ValueTask.FromException(DisposeFailure);
        }
    }

    [Fact]
    public void Constructing_the_service_does_not_touch_JavaScript()
    {
        // A Blazor Hybrid host builds its service provider before the WebView can run JavaScript (#634)
        var js = new FakeJSRuntime();

        _ = new WebAuthn(js);

        Assert.Empty(js.Calls);
    }

    [Fact]
    public async Task The_module_is_imported_on_first_use_and_only_once()
    {
        var js = new FakeJSRuntime();
        js.Module.Results["isWebAuthnPossible"] = true;
        var webAuthn = new WebAuthn(js);

        Assert.True(await webAuthn.IsWebAuthnSupportedAsync());
        Assert.True(await webAuthn.IsWebAuthnSupportedAsync());
        await webAuthn.Init();

        var import = Assert.Single(js.Calls);
        Assert.Equal("import", import.Identifier);
        Assert.Equal(ModulePath, Assert.Single(import.Args!));
        Assert.Equal(2, js.Module.Calls.Count);
    }

    [Fact]
    public async Task A_failed_import_is_retried_on_the_next_call()
    {
        var js = new FakeJSRuntime { ImportFailure = new JSException("Failed to fetch dynamically imported module") };
        js.Module.Results["isWebAuthnPossible"] = true;
        var webAuthn = new WebAuthn(js);

        await Assert.ThrowsAsync<JSException>(() => webAuthn.Init());
        await Assert.ThrowsAsync<JSException>(() => webAuthn.IsWebAuthnSupportedAsync());

        // The page has loaded now
        js.ImportFailure = null;

        Assert.True(await webAuthn.IsWebAuthnSupportedAsync());
        Assert.Equal(3, js.Calls.Count);
    }

    [Fact]
    public async Task Each_operation_calls_its_JavaScript_function_with_the_options()
    {
        var js = new FakeJSRuntime();
        var webAuthn = new WebAuthn(js);

        var creation = new CredentialCreateOptions
        {
            Challenge = [1, 2, 3],
            Rp = new PublicKeyCredentialRpEntity("example.com", "Example", null),
            User = new Fido2User { Id = [1], Name = "user", DisplayName = "User" },
            PubKeyCredParams = PubKeyCredParam.Defaults,
        };
        var created = new AuthenticatorAttestationRawResponse { Id = "AQID", RawId = [1, 2, 3], Type = PublicKeyCredentialType.PublicKey };
        js.Module.Results["createCreds"] = created;

        Assert.Same(created, await webAuthn.CreateCredsAsync(creation));
        Assert.Same(creation, Assert.Single(js.Module.Calls.Single(c => c.Identifier == "createCreds").Args!));

        var assertion = new AssertionOptions { Challenge = [4, 5, 6] };
        var asserted = new AuthenticatorAssertionRawResponse { Id = "BAUG", RawId = [4, 5, 6], Type = PublicKeyCredentialType.PublicKey };
        js.Module.Results["verify"] = asserted;

        Assert.Same(asserted, await webAuthn.VerifyAsync(assertion));
        Assert.Same(assertion, Assert.Single(js.Module.Calls.Single(c => c.Identifier == "verify").Args!));
    }

    [Fact]
    public async Task Disposing_the_service_disposes_the_module_it_imported()
    {
        var js = new FakeJSRuntime();
        var webAuthn = new WebAuthn(js);

        // Never imported: nothing to dispose
        await webAuthn.DisposeAsync();
        Assert.False(js.Module.Disposed);

        await webAuthn.Init();
        await webAuthn.DisposeAsync();
        Assert.True(js.Module.Disposed);
    }

    [Fact]
    public async Task Disposing_after_the_circuit_is_gone_does_not_throw()
    {
        var js = new FakeJSRuntime();
        js.Module.DisposeFailure = new JSDisconnectedException("circuit gone");
        var webAuthn = new WebAuthn(js);

        await webAuthn.Init();
        await webAuthn.DisposeAsync();

        Assert.True(js.Module.Disposed);
    }

    [Fact]
    public async Task AddWebAuthn_registers_the_service_as_scoped()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IJSRuntime>(new FakeJSRuntime());

        services.AddWebAuthn();

        var descriptor = Assert.Single(services, s => s.ServiceType == typeof(WebAuthn));
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);

        using var provider = services.BuildServiceProvider();

        // One instance per scope, and a scope disposed either way releases it
        using (var scope = provider.CreateScope())
        {
            Assert.Same(scope.ServiceProvider.GetRequiredService<WebAuthn>(), scope.ServiceProvider.GetRequiredService<WebAuthn>());
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            Assert.NotNull(scope.ServiceProvider.GetRequiredService<WebAuthn>());
        }
    }

    [Fact]
    public async Task Disposing_synchronously_releases_the_module_too()
    {
        var js = new FakeJSRuntime();
        var webAuthn = new WebAuthn(js);
        await webAuthn.Init();

        webAuthn.Dispose();

        Assert.True(js.Module.Disposed);
    }
}
