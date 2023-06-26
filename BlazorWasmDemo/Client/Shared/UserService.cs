namespace BlazorWasmDemo.Client.Shared;

using System.Net.Http.Json;
using Fido2.BlazorWebAssembly;
using Fido2NetLib;

public class UserService
{
    private const string _routeUser = "api/user";
    private const string _routeCredOptions = "credential-options";
    private const string _routeRegister = "credential";
    private const string _routeAssertionOpts = "assertion-options";
    private const string _routeLogin = "assertion";

    private readonly HttpClient _httpClient;
    private readonly WebAuthn _webAuthn;

    public UserService(HttpClient httpClient, WebAuthn webAuthn)
    {
        _httpClient = httpClient;
        _webAuthn = webAuthn;
    }

    public async Task<string> RegisterAsync(string? username, string? displayName)
    {
        // Make sure the WebAuthn API is initialized (although that should happen almost immediately after startup)
        await _webAuthn.Init();

        // Build the route to get options
        var routeOpts = _routeUser
                    + (string.IsNullOrEmpty(username) ? string.Empty : $"/{username}") // Query specific user unless we go usernameless
                    + $"/{_routeCredOptions}";

        // Add display name if set
        var query = string.IsNullOrEmpty(displayName) ? string.Empty : $"?displayName={displayName}";

        // Now the magic happens so stuff can go wrong
        try
        {
            // Get options from server
            var options = await _httpClient.GetFromJsonAsync<CredentialCreateOptions>(routeOpts + query);
            if(options == null)
            {
                return "No options received";
            }

            // Present options to user and get response
            var credential = await _webAuthn.CreateCredsAsync(options);

            // Send response to server
            return await (await _httpClient.PutAsJsonAsync($"{_routeUser}/{options.User.Name}/{_routeRegister}", credential)).Content.ReadAsStringAsync();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return e.Message;
        }
    }

    public async Task<string> LoginAsync(string? username)
    {
        // Make sure the WebAuthn API is initialized (although that should happen almost immediately after startup)
        await _webAuthn.Init();

        // Build the route to get options
        var route = _routeUser
                    + (string.IsNullOrEmpty(username) ? string.Empty : $"/{username}") // Query specific user unless we go usernameless
                    + $"/{_routeAssertionOpts}";

        // Now the magic happens so stuff can go wrong
        try
        {
            // Get options from server
            var options = await _httpClient.GetFromJsonAsync<AssertionOptions>(route);
            if (options == null)
            {
                return "No options received";
            }

            if (options.Status != "ok")
            {
                return options.ErrorMessage;
            }

            // Present options to user and get response (usernameless users will be asked by their authenticator, which credential they want to use to sign the challenge)
            var assertion = await _webAuthn.VerifyAsync(options);

            // Send response to server
            return await (await _httpClient.PostAsJsonAsync($"{_routeUser}/{_routeLogin}", assertion)).Content.ReadAsStringAsync();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<bool> IsWebAuthnSupportedAsync()
    {
        await _webAuthn.Init();
        return await _webAuthn.IsWebAuthnSupportedAsync();
    }
}
