namespace BlazorWasmDemo.Client.Shared;

using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

using Fido2.BlazorWebAssembly;

using Fido2NetLib;
using Fido2NetLib.Objects;

public class UserService
{
    private const string _routeUser = "api/user";
    private const string _routeCredOptions = "credential-options";
    private const string _routeRegister = "credential";
    private const string _routeAssertionOpts = "assertion-options";
    private const string _routeLogin = "assertion";

    private readonly JsonSerializerOptions _jsonOptions = new FidoBlazorSerializerContext().Options;
    private readonly HttpClient _httpClient;
    private readonly WebAuthn _webAuthn;

    public UserService(HttpClient httpClient, WebAuthn webAuthn)
    {
        _httpClient = httpClient;
        _webAuthn = webAuthn;
    }

    public async Task<string> RegisterAsync(string? username, string? displayName = null,
        AttestationConveyancePreference? attestationType = null, AuthenticatorAttachment? authenticator = null,
        UserVerificationRequirement? userVerification = null, ResidentKeyRequirement? residentKey = null)
    {
        // Make sure the WebAuthn API is initialized (although that should happen almost immediately after startup)
        await _webAuthn.Init();

        // Build the route to get options
        var routeOpts = _routeUser
                    + (string.IsNullOrEmpty(username) ? string.Empty : $"/{username}") // Query specific user unless we go usernameless
                    + $"/{_routeCredOptions}";

        // Add optional parameters if set
        var optionalParams = new List<string>();
        if (!string.IsNullOrEmpty(displayName))
        {
            optionalParams.Add($"{nameof(displayName)}={displayName}");
        }

        if (attestationType.HasValue)
        {
            optionalParams.Add($"{nameof(attestationType)}={attestationType}");
        }

        if (authenticator.HasValue)
        {
            optionalParams.Add($"{nameof(authenticator)}={authenticator}");
        }

        if (userVerification.HasValue)
        {
            optionalParams.Add($"{nameof(userVerification)}={userVerification}");
        }

        if (residentKey.HasValue)
        {
            optionalParams.Add($"{nameof(residentKey)}={residentKey}");
        }

        var query = "";
        if (optionalParams.Any())
        {
            query = "?" + string.Join("&", optionalParams);
        }

        // Now the magic happens so stuff can go wrong
        CredentialCreateOptions? options;
        try
        {
            // Get options from server
            options = await _httpClient.GetFromJsonAsync<CredentialCreateOptions>(routeOpts + query, _jsonOptions);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return e.Message;
        }

        if (options == null)
        {
            return "No options received";
        }

        // Build the route to register the credentials
        var routeCreds = $"{_routeUser}/{username ?? Convert.ToBase64String(Encoding.UTF8.GetBytes(options.User.Name))}/{_routeRegister}";

        try
        {
            // Present options to user and get response
            var credential = await _webAuthn.CreateCredsAsync(options);

            // Send response to server
            return await (await _httpClient.PutAsJsonAsync(routeCreds, credential, _jsonOptions)).Content.ReadAsStringAsync();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            var errorMessage = e.Message;
            if (options.ExcludeCredentials?.Count > 0)
            {
                errorMessage += " (You may have already registered this device)";
            }
            return errorMessage;
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
            var options = await _httpClient.GetFromJsonAsync<AssertionOptions>(route, _jsonOptions);
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
            return await (await _httpClient.PostAsJsonAsync($"{_routeUser}/{_routeLogin}", assertion, _jsonOptions)).Content.ReadAsStringAsync();
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
