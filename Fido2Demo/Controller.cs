using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib.Objects;
using Fido2NetLib;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Fido2NetLib.Development;
using static Fido2NetLib.Fido2;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Fido2Demo
{

    [Route("api/[controller]")]
    public class MyController : Controller
    {
        private Fido2 _lib;
        private IMetadataService _mds;
        private static readonly DevelopmentInMemoryStore DemoStorage = new DevelopmentInMemoryStore();

        public MyController(IConfiguration config)
        {
            var MDSAccessKey = config["fido2:MDSAccessKey"];
            _mds = string.IsNullOrEmpty(MDSAccessKey) ? null : MDSMetadata.Instance(MDSAccessKey, config["fido2:MDSCacheDirPath"]);
            _lib = new Fido2(new Configuration()
            {
                ServerDomain = config["fido2:serverDomain"],
                ServerName = "Fido2 test",
                Origin = config["fido2:origin"],
                // Only create and use Metadataservice if we have and acesskey
                MetadataService = _mds
            });
        }

        private string FormatException(Exception e)
        {
            return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
        }

        [HttpGet]
        [Route("/dashboard/{username}")]
        public ContentResult Index(string username)
        {
            // 1. Get user from DB
            var user = DemoStorage.GetUser(username + "@example.com");
            if (user == null) throw new ArgumentException("Username was not registered");

            // 2. Get registered credentials from database
            var existingCredentials = DemoStorage.GetCredentialsByUser(user);

            var content = System.IO.File.ReadAllText("wwwroot/index.html");

            content += "<h3 id=\"creds\">Credentials for " + username + "</h3>" +
            "<table class=\"table\">" + 
                "<tr>" +
                    "<th> Attestation Type</th>" +
                    "<th class=\"no-wrap\">Create Date</th>" +
                    "<th>Counter</th>" +
                    "<th>AAGUID</th>" +
                    "<th>Description</th>" +
                    "<th>Public Key</th>" +
                "</tr>";
            foreach (var cred in existingCredentials)
            {
                var coseKey = PeterO.Cbor.CBORObject.DecodeFromBytes(cred.PublicKey);
                var kty = coseKey[PeterO.Cbor.CBORObject.FromObject(1)].AsInt32();
                var desc = "";
                try { desc = _mds.GetEntry(cred.AaGuid).MetadataStatement.Description.ToString(); }
                catch { Exception ex; }

                content +=
                    "<tr>" +
                        "<td class=\"format no-wrap\">" + cred.CredType + "</td>" +
                        "<td class=\"no-wrap\">" + cred.RegDate + "</td>" +
                        "<td class=\"no-wrap\">" + cred.SignatureCounter.ToString() + "</td>" +
                        "<td class=\"no-wrap\">" + cred.AaGuid.ToString() + "</td>" +
                        "<td class=\"no-wrap\">" + desc + "</td>" +
                                            "<td>";
                switch (kty)
                {
                    case 1:
                        {
                            throw new Fido2VerificationException("Where did you find this device?");
                        }
                    case 2:
                        {
                            var X = coseKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString();
                            var Y = coseKey[PeterO.Cbor.CBORObject.FromObject(-3)].GetByteString();
                            content += "<table class=\"sub-table\">" +
                                    "<tr>" +
                                        "<td><pre>X: " + BitConverter.ToString(X).Replace("-", "") + "</pre></td>" +
                                    "</tr>" +
                                    "<tr>" +
                                        "<td><pre>Y: " + BitConverter.ToString(Y).Replace("-", "") + "</pre></td>" +
                                    "</tr>" +
                                    "</table>";
                            break;
                        }
                    case 3:
                        {
                            var modulus = coseKey[PeterO.Cbor.CBORObject.FromObject(-1)].GetByteString();
                            var exponent = coseKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString();
                            content += "<table class=\"sub-table\">" +
                                    "<tr>" +
                                        "<td><pre>Modulus: " + BitConverter.ToString(modulus).Replace("-", "") + "</pre></td>" +
                                    "</tr>" +
                                    "<tr>" +
                                        "<td><pre>Exponent: " + BitConverter.ToString(exponent).Replace("-", "") + "</pre></td>" +
                                    "</tr>" +
                                "</table>";
                            break;
                        }
                    default:
                        {
                            throw new Fido2VerificationException("Missing or unknown keytype");
                        }
                }
                    content += "</td></tr>";
            }
            content += "</table></div></div></body>";
            return new ContentResult
            {
                ContentType = "text/html",
                StatusCode = (int)System.Net.HttpStatusCode.OK,
                Content = content
            };
        }

        [HttpPost]
        [Route("/makeCredentialOptions")]
        public JsonResult MakeCredentialOptions([FromForm] string username, [FromForm] string attType, [FromForm] string authType, [FromForm] bool requireResidentKey, [FromForm] string userVerification)
        {
            try
            {
                // 1. Get user from DB by username (in our example, auto create missing users)
                var user = DemoStorage.GetOrAddUser(username, () => new User
                {
                    DisplayName = "Display " + username,
                    Name = username,
                    Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
                });

                // 2. Get user existing keys by username
                var existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

                // 3. Create options
                var authenticatorSelection = new AuthenticatorSelection
                {
                    RequireResidentKey = requireResidentKey,
                    UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
                };

                if (!string.IsNullOrEmpty(authType))
                    authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

                var options = _lib.RequestNewCredential(user, existingKeys, authenticatorSelection, attType.ToEnum<AttestationConveyancePreference>());

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
        public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
        {
            try
            {
                // 1. get the options we sent the client
                var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
                var options = CredentialCreateOptions.FromJson(jsonOptions);

                // 2. Create callback so that lib can verify credential id is unique to this user
                IsCredentialIdUniqueToUserAsyncDelegate callback = async (IsCredentialIdUniqueToUserParams args) =>
                {
                    var users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId);
                    if (users.Count > 0) return false;

                    return true;
                };

                // 2. Verify and make the credentials
                var success = await _lib.MakeNewCredentialAsync(attestationResponse, options, callback);

                // 3. Store the credentials in db
                DemoStorage.AddCredentialToUser(options.User, new StoredCredential
                {
                    Descriptor = new PublicKeyCredentialDescriptor(success.Result.CredentialId),
                    PublicKey = success.Result.PublicKey,
                    UserHandle = success.Result.User.Id,
                    SignatureCounter = success.Result.Counter,
                    CredType = success.Result.CredType,
                    RegDate = DateTime.Now,
                    AaGuid = success.Result.Aaguid
                });

                // 4. return "ok" to the client
                return Json(success);
            }
            catch (Exception e)
            {
                return Json(new CredentialMakeResult { Status = "error", ErrorMessage = FormatException(e) });
            }
        }

        [HttpPost]
        [Route("/assertionOptions")]
        public ActionResult AssertionOptionsPost([FromForm] string username)
        {
            try
            {
                // 1. Get user from DB
                var user = DemoStorage.GetUser(username);
                if (user == null) throw new ArgumentException("Username was not registered");

                // 2. Get registered credentials from database
                var existingCredentials = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
                
                // 3. Create options
                var options = _lib.GetAssertionOptions(
                    existingCredentials,
                    UserVerificationRequirement.Discouraged
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
        public async Task<JsonResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse)
        {
            try
            {
                // 1. Get the assertion options we sent the client
                var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
                var options = AssertionOptions.FromJson(jsonOptions);

                // 2. Get registered credential from database
                var creds = DemoStorage.GetCredentialById(clientResponse.Id);

                // 3. Get credential counter from database
                var storedCounter = creds.SignatureCounter;

                // 4. Create callback to check if userhandle owns the credentialId
                IsUserHandleOwnerOfCredentialIdAsync callback = async (args) =>
                {
                    var storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle);
                    return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
                };

                // 5. Make the assertion
                var res = await _lib.MakeAssertionAsync(clientResponse, options, creds.PublicKey, storedCounter, callback);

                // 6. Store the updated counter
                DemoStorage.UpdateCounter(res.CredentialId, res.Counter);

                // 7. return OK to client
                return Json(res);
            }
            catch (Exception e)
            {
                return Json(new AssertionVerificationResult { Status = "error", ErrorMessage = FormatException(e) });
            }
        }
    }
}
