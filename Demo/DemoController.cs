#nullable enable

using System.Buffers.Text;
using System.Text;

using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;

using Microsoft.AspNetCore.Mvc;

namespace Fido2Demo;

[Route("api/[controller]")]
public class DemoController : Controller
{
    private readonly IFido2 _fido2;
    private readonly Fido2Configuration _config;
    public static readonly DevelopmentInMemoryStore DemoStorage = new();

    public DemoController(IFido2 fido2, Fido2Configuration config)
    {
        _fido2 = fido2;
        _config = config;
    }

    private string FormatException(Exception e)
    {
        return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
    }

    /// <summary>
    /// Parses a value posted by the demo's option controls. An empty control means "let the Relying Party
    /// decide", so it falls back to <paramref name="fallback"/> rather than throwing: ToEnum on an empty string
    /// raises "Value cannot be null. (Parameter 'key')", which tells the user nothing about what went wrong.
    /// </summary>
    private static TEnum ToEnumOrDefault<TEnum>(string value, TEnum fallback) where TEnum : struct, Enum
    {
        if (string.IsNullOrWhiteSpace(value))
            return fallback;

        try
        {
            return value.ToEnum<TEnum>();
        }
        catch (ArgumentException)
        {
            return fallback;
        }
    }

    /// <summary>
    /// Parses a comma-separated list of enum values, skipping anything unrecognized. Used for the L3 members
    /// that take a sequence -- hints and attestationFormats -- both of which are advisory, so an unknown entry
    /// is dropped rather than failing the ceremony.
    /// </summary>
    private static List<TEnum> ToEnumList<TEnum>(string value) where TEnum : struct, Enum
    {
        var result = new List<TEnum>();

        if (string.IsNullOrWhiteSpace(value))
            return result;

        foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                result.Add(part.ToEnum<TEnum>());
            }
            catch (ArgumentException)
            {
                // An unrecognized hint or attestation format is advisory only; drop it.
            }
        }

        return result;
    }

    [HttpPost]
    [Route("/makeCredentialOptions")]
    public JsonResult MakeCredentialOptions([FromForm] string username,
                                            [FromForm] string displayName,
                                            [FromForm] string attType,
                                            [FromForm] string authType,
                                            [FromForm] string residentKey,
                                            [FromForm] string userVerification,
                                            [FromForm] string hints,
                                            [FromForm] string attestationFormats,
                                            [FromForm] string prf)
    {
        try
        {

            if (string.IsNullOrEmpty(username))
            {
                username = $"{displayName} (Usernameless user created at {DateTime.UtcNow})";
            }

            // 1. Get user from DB by username (in our example, auto create missing users)
            var user = DemoStorage.GetOrAddUser(username, () => new Fido2User
            {
                DisplayName = displayName,
                Name = username,
                Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
            });

            // 2. Get user existing keys by username
            var existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

            // 3. Create options
            var authenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = ToEnumOrDefault(residentKey, ResidentKeyRequirement.Discouraged),
                UserVerification = ToEnumOrDefault(userVerification, UserVerificationRequirement.Preferred)
            };

            if (!string.IsNullOrEmpty(authType))
                authenticatorSelection.AuthenticatorAttachment = ToEnumOrDefault<AuthenticatorAttachment>(authType, default);

            var exts = new AuthenticationExtensionsClientInputs()
            {
                CredProps = true
            };

            // WebAuthn L3 SS10.1.4: the prf extension asks the authenticator to evaluate a PRF over the inputs.
            // At registration no eval input is supplied -- the RP is only asking whether prf is available, which
            // the client reports back as prf.enabled.
            if (prf == "true")
                exts.PRF = new AuthenticationExtensionsPRFInputs();

            var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
            {
                User = user,
                ExcludeCredentials = existingKeys,
                AuthenticatorSelection = authenticatorSelection,
                AttestationPreference = ToEnumOrDefault(attType, AttestationConveyancePreference.None),
                Extensions = exts,

                // WebAuthn L3 SS5.8.8: hints guide how the user agent presents the ceremony. Advisory only.
                Hints = ToEnumList<PublicKeyCredentialHint>(hints),

                // WebAuthn L3 SS5.4: the attestation statement formats this RP prefers, most preferred first.
                AttestationFormats = ToEnumList<AttestationStatementFormatIdentifier>(attestationFormats)
            });

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            // 5. return options to client
            return Json(options);
        }
        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeCredential")]
    public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse,
                                                 [FromQuery] string mediation,
                                                 CancellationToken cancellationToken)
    {
        try
        {
            // 1. get the options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions")
                ?? throw new InvalidOperationException("Registration session expired. Start the registration again.");
            var options = CredentialCreateOptions.FromJson(jsonOptions);

            // 2. Create callback so that lib can verify credential id is unique to this user
            IsCredentialIdUniqueToUserAsyncDelegate callback = static async (args, cancellationToken) =>
            {
                var users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId, cancellationToken);
                if (users.Count > 0)
                    return false;

                return true;
            };

            // 2. Verify and make the credentials
            var credential = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = options,
                IsCredentialIdUniqueToUserCallback = callback,

                // WebAuthn L3 SS5.1.3: a conditional create is performed without a modal prompt, so the
                // authenticator does not test user presence and the UP flag is not required to be set. The
                // library needs to be told which kind of ceremony this was.
                Mediation = ToEnumOrDefault(mediation, CredentialMediationRequirement.Optional)
            }, cancellationToken: cancellationToken);

            // 3. Store the credentials in db
            DemoStorage.AddCredentialToUser(options.User, new StoredCredential
            {
                Id = credential.Id,
                PublicKey = credential.PublicKey,
                UserHandle = credential.User.Id,
                SignCount = credential.SignCount,
                AttestationFormat = credential.AttestationFormat,
                RegDate = DateTimeOffset.UtcNow,
                AaGuid = credential.AaGuid,
                Transports = credential.Transports,
                AuthenticatorAttachment = credential.AuthenticatorAttachment,
                UvInitialized = credential.UvInitialized,
                IsBackupEligible = credential.IsBackupEligible,
                IsBackedUp = credential.IsBackedUp,
                AttestationObject = credential.AttestationObject,
                AttestationClientDataJson = credential.AttestationClientDataJson,

                // WebAuthn L3 SS10.1.3: credProps.rk is three-state. null means the client did not say whether
                // the credential is discoverable, which is different from saying it is not.
                IsDiscoverable = attestationResponse.ClientExtensionResults?.CredProps?.Rk
            });

            // 4. return "ok" to the client
            return Json(credential);
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/assertionOptions")]
    public ActionResult AssertionOptionsPost([FromForm] string username,
                                             [FromForm] string userVerification,
                                             [FromForm] string hints)
    {
        try
        {
            List<PublicKeyCredentialDescriptor> existingCredentials = [];

            if (!string.IsNullOrEmpty(username))
            {
                // 1. Get user from DB
                var user = DemoStorage.GetUser(username) ?? throw new ArgumentException("Username was not registered");

                // 2. Get registered credentials from database
                existingCredentials = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
            }

            // 3. Create options
            var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams()
            {
                AllowedCredentials = existingCredentials,
                UserVerification = ToEnumOrDefault(userVerification, UserVerificationRequirement.Discouraged),
                Hints = ToEnumList<PublicKeyCredentialHint>(hints)
            });

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

            // 5. Return options to client
            return Json(options);
        }

        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeAssertion")]
    public async Task<JsonResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. Get the assertion options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions")
                ?? throw new InvalidOperationException("Sign-in session expired. Start the sign-in again.");
            var options = AssertionOptions.FromJson(jsonOptions);

            // 2. Get registered credential from database
            var creds = DemoStorage.GetCredentialById(clientResponse.RawId) ?? throw new Exception("Unknown credentials");

            // 3. Get credential counter from database
            var storedCounter = creds.SignCount;

            // 4. Create callback to check if the user handle owns the credentialId
            IsUserHandleOwnerOfCredentialIdAsync callback = static async (args, cancellationToken) =>
            {
                var storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle, cancellationToken);
                return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
            };

            // 5. Make the assertion
            var res = await _fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = clientResponse,
                OriginalOptions = options,
                StoredPublicKey = creds.PublicKey,
                StoredSignatureCounter = storedCounter,
                StoredBackupEligible = creds.IsBackupEligible,
                IsUserHandleOwnerOfCredentialIdCallback = callback
            }, cancellationToken: cancellationToken);

            // 6. Store the updated credential record state (counter, backup state, uvInitialized)
            DemoStorage.UpdateCredentialRecord(res);

            // 7. return OK to client
            return Json(res);
        }
        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // WebAuthn L3 SS5.1.10 signal methods.
    //
    // These let a Relying Party tell the authenticator that its view of a credential is stale, so a passkey
    // provider can hide or relabel entries the RP no longer accepts. The browser makes the call; the server's
    // job is to produce the payload. They are best-effort and report no result, so nothing here should be
    // treated as a security boundary.
    // ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// Payload for <c>PublicKeyCredential.signalUnknownCredential()</c>: this credential ID is not one we
    /// recognize, so the authenticator may remove or hide it.
    /// </summary>
    [HttpPost]
    [Route("/signal/unknownCredential")]
    public JsonResult SignalUnknownCredential([FromForm] string credentialId)
    {
        try
        {
            var options = new UnknownCredentialOptions
            {
                RpId = _config.RPID,
                CredentialId = Base64Url.DecodeFromChars(credentialId)
            };

            return Json(options);
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = FormatException(e) });
        }
    }

    /// <summary>
    /// Payload for <c>PublicKeyCredential.signalAllAcceptedCredentials()</c>: the complete set of credential
    /// IDs still accepted for this user.
    /// </summary>
    /// <remarks>
    /// The list MUST be exhaustive. An authenticator may delete credentials missing from it, so a Relying Party
    /// that cannot enumerate every credential for the user should not call this at all.
    /// </remarks>
    [HttpPost]
    [Route("/signal/allAcceptedCredentials")]
    public JsonResult SignalAllAcceptedCredentials([FromForm] string username)
    {
        try
        {
            var user = DemoStorage.GetUser(username) ?? throw new ArgumentException("Username was not registered");
            var credentials = DemoStorage.GetCredentialsByUser(user);

            var options = new AllAcceptedCredentialsOptions
            {
                RpId = _config.RPID,
                UserId = user.Id,
                AllAcceptedCredentialIds = credentials.Select(c => c.Id).ToList()
            };

            return Json(options);
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = FormatException(e) });
        }
    }

    /// <summary>
    /// Payload for <c>PublicKeyCredential.signalCurrentUserDetails()</c>: the name and display name the
    /// authenticator should now show for this user's credentials.
    /// </summary>
    [HttpPost]
    [Route("/signal/currentUserDetails")]
    public JsonResult SignalCurrentUserDetails([FromForm] string username)
    {
        try
        {
            var user = DemoStorage.GetUser(username) ?? throw new ArgumentException("Username was not registered");

            var options = new CurrentUserDetailsOptions
            {
                RpId = _config.RPID,
                UserId = user.Id,
                Name = user.Name,
                DisplayName = user.DisplayName
            };

            return Json(options);
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = FormatException(e) });
        }
    }
}
