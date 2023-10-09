namespace BlazorWasmDemo.Server.Controllers;

using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;

using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private static readonly SigningCredentials _signingCredentials = new(
        new SymmetricSecurityKey("This is my very long and totally secret key for signing tokens, which clients may never learn or I'd have to replace it."u8.ToArray()),
        SecurityAlgorithms.HmacSha256
    );

    private static readonly DevelopmentInMemoryStore _demoStorage = new();
    private static readonly Dictionary<string, CredentialCreateOptions> _pendingCredentials = new();
    private static readonly Dictionary<string, AssertionOptions> _pendingAssertions = new();
    private readonly IFido2 _fido2;

    private static string FormatException(Exception e) => $"{e.Message}{e.InnerException?.Message ?? string.Empty}";

    public UserController(IFido2 fido2)
    {
        _fido2 = fido2;
    }

    /// <summary>
    /// Creates options to create a new credential for a user.
    /// </summary>
    /// <param name="username">(optional) The user's internal identifier. Omit for usernameless account.</param>
    /// <param name="displayName">(optional as query) Name for display purposes.</param>
    /// <param name="attestationType">(optional as query)</param>
    /// <param name="authenticator">(optional as query)</param>
    /// <param name="userVerification">(optional as query)</param>
    /// <param name="residentKey">(optional as query)</param>
    /// <returns>A new <see cref="CredentialCreateOptions"/>. Contains an error message if .Status is "error".</returns>
    [HttpGet("{username}/credential-options")]
    [HttpGet("credential-options")]
    public CredentialCreateOptions GetCredentialOptions(
        [FromRoute] string? username,
        [FromQuery] string? displayName,
        [FromQuery] AttestationConveyancePreference? attestationType,
        [FromQuery] AuthenticatorAttachment? authenticator,
        [FromQuery] UserVerificationRequirement? userVerification,
        [FromQuery] ResidentKeyRequirement? residentKey)
    {
        try
        {
            var key = username;
            if (string.IsNullOrEmpty(username))
            {
                var created = DateTime.UtcNow;
                if (string.IsNullOrEmpty(displayName))
                {
                    // More precise generated name for less collisions in _pendingCredentials
                    username = $"(Usernameless user created {created})";
                }
                else
                {
                    // Less precise but nicer for user if there's a displayName set anyway
                    username = $"{displayName} (Usernameless user created {created.ToShortDateString()})";
                }
                key = Convert.ToBase64String(Encoding.UTF8.GetBytes(username));
            }
            Debug.Assert(key != null); // If it was null before, it was set to the base64 value. Analyzer doesn't understand this though.

            // 1. Get user from DB by username (in our example, auto create missing users)
            var user = _demoStorage.GetOrAddUser(username, () => new Fido2User
            {
                DisplayName = displayName,
                Name = username,
                Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
            });

            // 2. Get user existing keys by username
            var existingKeys = _demoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

            // 3. Build authenticator selection
            var authenticatorSelection = AuthenticatorSelection.Default;
            if (authenticator != null)
            {
                authenticatorSelection.AuthenticatorAttachment = authenticator;
            }

            if (userVerification != null)
            {
                authenticatorSelection.UserVerification = userVerification.Value;
            }

            if (residentKey != null)
            {
                authenticatorSelection.ResidentKey = residentKey.Value;
            }

            // 4. Create options
            var options = _fido2.RequestNewCredential(
                user,
                existingKeys,
                authenticatorSelection,
                attestationType ?? AttestationConveyancePreference.None,
                new AuthenticationExtensionsClientInputs
                {
                    Extensions = true,
                    UserVerificationMethod = true,
                    CredProps = true,
                    DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs
                    {
                        Attestation = attestationType?.ToString() ?? AttestationConveyancePreference.None.ToString()
                    },
                }
            );

            // 5. Temporarily store options, session/in-memory cache/redis/db
            _pendingCredentials[key] = options;

            // 6. return options to client
            return options;
        }
        catch (Exception e)
        {
            return new CredentialCreateOptions { Status = "error", ErrorMessage = FormatException(e) };
        }
    }

    /// <summary>
    /// Creates a new credential for a user.
    /// </summary>
    /// <param name="username">Username of registering user. If usernameless, use base64 encoded options.User.Name from the credential-options used to create the credential.</param>
    /// <param name="attestationResponse"></param>
    /// <param name="cancellationToken"></param>
    /// <returns>a string containing either "OK" or an error message.</returns>
    [HttpPut("{username}/credential")]
    public async Task<string> CreateCredentialAsync([FromRoute] string username, [FromBody] AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. Get the options we sent the client
            var options = _pendingCredentials[username];

            // 2. Create callback so that lib can verify credential id is unique to this user

            // 3. Verify and make the credentials
            var result = await _fido2.MakeNewCredentialAsync(attestationResponse, options, CredentialIdUniqueToUserAsync, cancellationToken: cancellationToken);

            if (result.Status is "error" || result.Result is null)
            {
                return result.ErrorMessage ?? string.Empty;
            }

            // 4. Store the credentials in db
            _demoStorage.AddCredentialToUser(options.User, new StoredCredential
            {
                AttestationFormat = result.Result.AttestationFormat,
                Id = result.Result.Id,
                Descriptor = new PublicKeyCredentialDescriptor(result.Result.Id),
                PublicKey = result.Result.PublicKey,
                UserHandle = result.Result.User.Id,
                SignCount = result.Result.SignCount,
                RegDate = DateTimeOffset.UtcNow,
                AaGuid = result.Result.AaGuid,
                DevicePublicKeys = new List<byte[]> { result.Result.DevicePublicKey },
                Transports = result.Result.Transports,
                IsBackupEligible = result.Result.IsBackupEligible,
                IsBackedUp = result.Result.IsBackedUp,
                AttestationObject = result.Result.AttestationObject,
                AttestationClientDataJSON = result.Result.AttestationClientDataJson,
            });

            // 5. Now we need to remove the options from the pending dictionary
            _pendingCredentials.Remove(Request.Host.ToString());

            // 5. return OK to client
            return "OK";
        }
        catch (Exception e)
        {
            return FormatException(e);
        }
    }

    private static async Task<bool> CredentialIdUniqueToUserAsync(IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken)
    {
        var users = await _demoStorage.GetUsersByCredentialIdAsync(args.CredentialId, cancellationToken);
        return users.Count <= 0;
    }

    [HttpGet("{username}/assertion-options")]
    [HttpGet("assertion-options")]
    public AssertionOptions MakeAssertionOptions([FromRoute] string? username, [FromQuery] UserVerificationRequirement? userVerification)
    {
        try
        {
            var existingKeys = new List<PublicKeyCredentialDescriptor>();
            if (!string.IsNullOrEmpty(username))
            {
                // 1. Get user and their credentials from DB
                var user = _demoStorage.GetUser(username);

                if (user != null)
                    existingKeys = _demoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
            }

            var exts = new AuthenticationExtensionsClientInputs
            {
                UserVerificationMethod = true,
                Extensions = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs()
            };

            // 2. Create options (usernameless users will be prompted by their device to select a credential from their own list)
            var options = _fido2.GetAssertionOptions(
                existingKeys,
                userVerification ?? UserVerificationRequirement.Discouraged,
                exts);

            // 4. Temporarily store options, session/in-memory cache/redis/db
            _pendingAssertions[new string(options.Challenge.Select(b => (char)b).ToArray())] = options;

            // 5. return options to client
            return options;
        }
        catch (Exception e)
        {
            return new AssertionOptions { Status = "error", ErrorMessage = FormatException(e) };
        }
    }

    /// <summary>
    /// Verifies an assertion response from a client, generating a new JWT for the user.
    /// </summary>
    /// <param name="clientResponse">The client's authenticator's response to the challenge.</param>
    /// <param name="cancellationToken"></param>
    /// <returns>
    /// Either a new JWT header or an error message.
    /// Example successful response:
    /// "Bearer eyyylmaooimtotallyatoken"
    /// Example error response:
    /// "Error: Invalid assertion"
    /// </returns>
    [HttpPost("assertion")]
    public async Task<string> MakeAssertionAsync([FromBody] AuthenticatorAssertionRawResponse clientResponse,
        CancellationToken cancellationToken)
    {
        try
        {
            // 1. Get the assertion options we sent the client remove them from memory so they can't be used again
            var response = JsonSerializer.Deserialize<AuthenticatorResponse>(clientResponse.Response.ClientDataJson);
            if (response is null)
            {
                return "Error: Could not deserialize client data";
            }

            var key = new string(response.Challenge.Select(b => (char)b).ToArray());
            if (!_pendingAssertions.TryGetValue(key, out var options))
            {
                return "Error: Challenge not found, please get a new one via GET /{username?}/assertion-options";
            }
            _pendingAssertions.Remove(key);

            // 2. Get registered credential from database
            var creds = _demoStorage.GetCredentialById(clientResponse.Id) ?? throw new Exception("Unknown credentials");

            // 3. Make the assertion
            var res = await _fido2.MakeAssertionAsync(
                clientResponse,
                options,
                creds.PublicKey,
                creds.DevicePublicKeys,
                creds.SignCount,
                UserHandleOwnerOfCredentialIdAsync,
                cancellationToken: cancellationToken);

            // 4. Store the updated counter
            if (res.Status is "ok")
            {
                _demoStorage.UpdateCounter(res.CredentialId, res.SignCount);
                if (res.DevicePublicKey is not null)
                {
                    creds.DevicePublicKeys.Add(res.DevicePublicKey);
                }
            }
            else
            {
                return $"Error: {res.ErrorMessage}";
            }

            // 5. return result to client
            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateEncodedJwt(
                HttpContext.Request.Host.Host,
                HttpContext.Request.Headers.Referer,
                new ClaimsIdentity(new Claim[] { new(ClaimTypes.Actor, Encoding.UTF8.GetString(creds.UserHandle)) }),
                DateTime.Now.Subtract(TimeSpan.FromMinutes(1)),
                DateTime.Now.AddDays(1),
                DateTime.Now,
                _signingCredentials,
                null);

            if (token is null)
            {
                return "Error: Token couldn't be created";
            }

            return $"Bearer {token}";
        }
        catch (Exception e)
        {
            return $"Error: {FormatException(e)}";
        }
    }

    private static async Task<bool> UserHandleOwnerOfCredentialIdAsync(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellationToken)
    {
        var storedCreds = await _demoStorage.GetCredentialsByUserHandleAsync(args.UserHandle, cancellationToken);
        return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
    }
}
