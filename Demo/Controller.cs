using System.Text;

using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;

using Microsoft.AspNetCore.Mvc;

namespace Fido2Demo;

[Route("api/[controller]")]
public class MyController : Controller
{
    private IFido2 _fido2;
    public static IMetadataService _mds;
    public static readonly DevelopmentInMemoryStore DemoStorage = new();

    public MyController(IFido2 fido2)
    {
        _fido2 = fido2;
    }

    private string FormatException(Exception e)
    {
        return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
    }

    [HttpPost]
    [Route("/makeCredentialOptions")]
    public JsonResult MakeCredentialOptions([FromForm] string username,
                                            [FromForm] string displayName,
                                            [FromForm] string attType,
                                            [FromForm] string authType,
                                            [FromForm] string residentKey,
                                            [FromForm] string userVerification)
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
                ResidentKey = residentKey.ToEnum<ResidentKeyRequirement>(),
                UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
            };

            if (!string.IsNullOrEmpty(authType))
                authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs() { Attestation = attType },
                CredProps = true
            };

            var options = _fido2.RequestNewCredential(user, existingKeys, authenticatorSelection, attType.ToEnum<AttestationConveyancePreference>(), exts);

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            // 5. return options to client
            return Json(options);
        }
        catch (Exception e)
        {
            return Json(new CredentialCreateOptions { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeCredential")]
    public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. get the options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
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
            var success = await _fido2.MakeNewCredentialAsync(attestationResponse, options, callback, cancellationToken: cancellationToken);

            // 3. Store the credentials in db
            DemoStorage.AddCredentialToUser(options.User, new StoredCredential
            {
                Id = success.Result.Id,
                PublicKey = success.Result.PublicKey,
                UserHandle = success.Result.User.Id,
                SignCount = success.Result.SignCount,
                AttestationFormat = success.Result.AttestationFormat,
                RegDate = DateTimeOffset.UtcNow,
                AaGuid = success.Result.AaGuid,
                Transports = success.Result.Transports,
                IsBackupEligible = success.Result.IsBackupEligible,
                IsBackedUp = success.Result.IsBackedUp,
                AttestationObject = success.Result.AttestationObject,
                AttestationClientDataJson = success.Result.AttestationClientDataJson,
                DevicePublicKeys = [success.Result.DevicePublicKey]
            });

            // 4. return "ok" to the client
            return Json(success);
        }
        catch (Exception e)
        {
            return Json(new MakeNewCredentialResult(status: "error", errorMessage: FormatException(e), result: null));
        }
    }

    [HttpPost]
    [Route("/assertionOptions")]
    public ActionResult AssertionOptionsPost([FromForm] string username, [FromForm] string userVerification)
    {
        try
        {
            var existingCredentials = new List<PublicKeyCredentialDescriptor>();

            if (!string.IsNullOrEmpty(username))
            {
                // 1. Get user from DB
                var user = DemoStorage.GetUser(username) ?? throw new ArgumentException("Username was not registered");

                // 2. Get registered credentials from database
                existingCredentials = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
            }

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs()
            };

            // 3. Create options
            var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
            var options = _fido2.GetAssertionOptions(
                existingCredentials,
                uv,
                exts
            );

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

            // 5. Return options to client
            return Json(options);
        }

        catch (Exception e)
        {
            return Json(new AssertionOptions { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeAssertion")]
    public async Task<JsonResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. Get the assertion options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
            var options = AssertionOptions.FromJson(jsonOptions);

            // 2. Get registered credential from database
            var creds = DemoStorage.GetCredentialById(clientResponse.Id) ?? throw new Exception("Unknown credentials");

            // 3. Get credential counter from database
            var storedCounter = creds.SignCount;

            // 4. Create callback to check if the user handle owns the credentialId
            IsUserHandleOwnerOfCredentialIdAsync callback = static async (args, cancellationToken) =>
            {
                var storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle, cancellationToken);
                return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
            };

            // 5. Make the assertion
            var res = await _fido2.MakeAssertionAsync(clientResponse, options, creds.PublicKey, creds.DevicePublicKeys, storedCounter, callback, cancellationToken: cancellationToken);

            // 6. Store the updated counter
            DemoStorage.UpdateCounter(res.CredentialId, res.SignCount);

            if (res.DevicePublicKey is not null)
                creds.DevicePublicKeys.Add(res.DevicePublicKey);

            // 7. return OK to client
            return Json(res);
        }
        catch (Exception e)
        {
            return Json(new VerifyAssertionResult { Status = "error", ErrorMessage = FormatException(e) });
        }
    }
}
