namespace Fido2.BlazorWebAssembly;

using Fido2NetLib;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;

/// <summary>
/// Module for accessing the browser's WebAuthn API.
/// </summary>
public class WebAuthn : IAsyncDisposable, IDisposable
{
    private const string ModulePath = "./_content/Fido2.BlazorWebAssembly/js/WebAuthn.js";

    private readonly IJSRuntime _js;
    private Task<IJSObjectReference>? _module;

    public WebAuthn(IJSRuntime js)
    {
        _js = js;
    }

    // The import is deferred to the first call rather than started in the constructor: a Blazor Hybrid host
    // builds its service provider before the WebView can run JavaScript, and Blazor Server only has a JS
    // runtime once the circuit is up, so importing from the constructor throws in both.
    private Task<IJSObjectReference> GetModuleAsync()
    {
        if (_module is null || _module.IsFaulted || _module.IsCanceled)
            _module = _js.InvokeAsync<IJSObjectReference>("import", ModulePath).AsTask();

        return _module;
    }

    /// <summary>
    /// Loads the JavaScript module. Calling this is optional; every other method loads it on first use.
    /// </summary>
    /// <returns></returns>
    public Task Init() => GetModuleAsync();

    /// <summary>
    /// Whether or not this browser supports WebAuthn.
    /// </summary>
    /// <returns></returns>
    public async Task<bool> IsWebAuthnSupportedAsync()
    {
        var module = await GetModuleAsync();
        return await module.InvokeAsync<bool>("isWebAuthnPossible");
    }

    /// <summary>
    /// Creates a new credential.
    /// </summary>
    /// <param name="options"></param>
    /// <returns></returns>
    public async Task<AuthenticatorAttestationRawResponse> CreateCredsAsync(CredentialCreateOptions options)
    {
        var module = await GetModuleAsync();
        return await module.InvokeAsync<AuthenticatorAttestationRawResponse>("createCreds", options);
    }

    /// <summary>
    /// Verifies a credential for login.
    /// </summary>
    /// <param name="options"></param>
    /// <returns></returns>
    public async Task<AuthenticatorAssertionRawResponse> VerifyAsync(AssertionOptions options)
    {
        var module = await GetModuleAsync();
        return await module.InvokeAsync<AuthenticatorAssertionRawResponse>("verify", options);
    }

    /// <summary>
    /// Releases the JavaScript module, if it was imported.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_module is { IsCompletedSuccessfully: true } module)
        {
            try
            {
                await module.Result.DisposeAsync();
            }
            catch (JSDisconnectedException)
            {
                // The circuit is already gone, and the module went with it.
            }
        }
    }

    /// <summary>
    /// Releases the JavaScript module without waiting for it. A container disposed synchronously cannot await, and
    /// would refuse a service that only offers <see cref="DisposeAsync"/>.
    /// </summary>
    public void Dispose()
    {
        _ = DisposeAsync().AsTask();
        GC.SuppressFinalize(this);
    }
}

public static class DependencyInjection
{
    /// <summary>
    /// Adds the <see cref="WebAuthn"/> service to the DI container.
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    // Scoped, not singleton: the service holds an IJSRuntime, which is per-circuit on Blazor Server and
    // per-WebView in Blazor Hybrid. In WebAssembly a scope lives as long as the app, so nothing changes there.
    public static IServiceCollection AddWebAuthn(this IServiceCollection services) =>
        services.AddScoped<WebAuthn>();
}
