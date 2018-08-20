using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib.Objects;
using Fido2NetLib;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Fido2NetLib.Development;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Fido2Demo
{

    [Route("api/[controller]")]
    public class MyController : Controller
    {
        private Fido2NetLib.Fido2 _lib;
        private static readonly DevelopmentInMemoryStore Storage = new DevelopmentInMemoryStore();

        public MyController(IConfiguration config)
        {
            _lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2.Configuration
            {
                ServerDomain = config["fido2:serverDomain"],
                ServerName = "Fido2 test",
                Origin = config["fido2:origin"]
            });
        }

        [HttpPost]
        [Route("/makeCredentialOptions")]
        public JsonResult MakeCredentialOptions([FromForm] string username, [FromForm] string attType)
        {
            // 1. Get user from DB by username (in our example, auto create missing users)
            var user = Storage.GetOrAddUser(username, () => new User
            {
                DisplayName = "Display " + username,
                Name = username,
                Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
            });

            // 2. Get user existing keys by username
            List<PublicKeyCredentialDescriptor> existingKeys = Storage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

            // 3. Create options
            var options = _lib.RequestNewCredential(user, existingKeys, AuthenticatorSelection.Default, AttestationConveyancePreference.Parse(attType));

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            // 5. return options to client
            return Json(options);
        }

        [HttpPost]
        [Route("/makeCredential")]
        public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse bodyRes)
        {
            // 1. get the options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
            var options = CredentialCreateOptions.FromJson(jsonOptions);

            // 2. Create callback so that lib can verify credential id is unique to this user
            IsCredentialIdUniqueToUserAsyncDelegate callback = async (IsCredentialIdUniqueToUserParams args) =>
            {
                List<User> users = await Storage.GetUsersByCredentialIdAsync(args.CredentialId);
                if (users.Count > 0) return false;

                return true;
            };

            // 2. Verify and make the credentials
            var success = await _lib.MakeNewCredentialAsync(bodyRes, options, callback);

            // 3. Store the credentials in db
            Storage.AddCredentialToUser(options.User, new StoredCredential
            {
                Descriptor = new PublicKeyCredentialDescriptor(success.Result.CredentialId),
                PublicKey = success.Result.PublicKey,
                UserHandle = success.Result.User.Id
            });

            // 4. return "ok" to the client
            return Json(success);
        }

        [HttpPost]
        [Route("/assertionOptions")]
        public ActionResult AssertionOptionsPost([FromForm] string username)
        {
            // 1. Get user from DB
            var user = Storage.GetUser(username);
            if (user == null) return NotFound("username was not registered");

            // 2. Get registered credentials from database
            List<PublicKeyCredentialDescriptor> existingCredentials = Storage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

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

        [HttpPost]
        [Route("/makeAssertion")]
        public async Task<JsonResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse)
        {

            // 1. Get the assertion options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
            var options = AssertionOptions.FromJson(jsonOptions);

            // 2. Get registered credential from database
            StoredCredential creds = Storage.GetCredentialById(clientResponse.Id);

            // 3. Get credential counter from database
            var storedCounter = creds.SignatureCounter;

            // 4. Create callback to check if userhandle owns the credentialId
            IsUserHandleOwnerOfCredentialIdAsync callback = async (args) =>
            {
                List<StoredCredential> storedCreds = await Storage.GetCredentialsByUserHandleAsync(args.UserHandle);
                return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
            };

            // 5. Make the assertion
            var res = await _lib.MakeAssertionAsync(clientResponse, options, creds.PublicKey, storedCounter, callback);

            // 6. Store the updated counter
            Storage.UpdateCounter(res.CredentialId, res.Counter);

            // 7. return OK to client
            return Json(res);
        }

        [HttpGet]
        [Route("/user/{username}")]
        public ActionResult GetUser(string username)
        {
            var jsonCreds = HttpContext.Session.GetString("fido2.creds");
            if (string.IsNullOrEmpty(jsonCreds))
            {
                Response.StatusCode = 401;
                return BadRequest("No user in HTTP Session (please register)");
            }
            return Ok();
        }



    }
}
