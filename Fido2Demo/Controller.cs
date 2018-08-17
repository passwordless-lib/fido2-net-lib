using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib.Objects;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Fido2Demo
{

    [Route("api/[controller]")]
    public class MyController : Controller
    {
        private Fido2NetLib.Fido2 _lib;

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
            var user = new User
            {
                DisplayName = "Display " + username,
                Name = username,
                Id = Encoding.UTF8.GetBytes("1")
            };

            var challenge = _lib.RequestNewCredential(user, null, null, attType);
            HttpContext.Session.Clear();
            HttpContext.Session.SetString("fido2.challenge", JsonConvert.SerializeObject(challenge));

            return Json(challenge);
        }

        [HttpPost]
        [Route("/makeCredential")]
        public Fido2NetLib.Fido2.CredentialMakeResult MakeCredential([FromBody] AuthenticatorAttestationRawResponse bodyRes)
        {
            var json = HttpContext.Session.GetString("fido2.challenge");
            var origChallenge = JsonConvert.DeserializeObject<CredentialCreateOptions>(json);

            var requestTokenBindingId = Request.HttpContext.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            var res = _lib.MakeNewCredential(bodyRes, origChallenge, requestTokenBindingId, (x) => true);

            HttpContext.Session.SetString("fido2.creds", JsonConvert.SerializeObject(res.Result));
            return res;
        }

        [HttpPost]
        [Route("/assertionOptions")]
        public JsonResult AssertionOptions(string username)
        {
            // todo: Fetch creds for the user from database.
            var jsonCreds = HttpContext.Session.GetString("fido2.creds");            
            var creds = JsonConvert.DeserializeObject<AttestationVerificationData>(jsonCreds);

            // get ID and displayname from DB
            var fakeUser = new User()
            {
                Id = Encoding.UTF8.GetBytes("1"),
                Name = username,
                DisplayName = "Display " + username
            };

            // get expected credentials from db 
            var allowedCredentials = new List<PublicKeyCredentialDescriptor>() {
                    new PublicKeyCredentialDescriptor()
                    {
                        Id = creds.CredentialId,
                        Type = "public-key"
                    }
            };

            var aoptions = _lib.GetAssertion(
                fakeUser,
                allowedCredentials,
                userVerification: UserVerificationRequirement.Preferred
            );

            HttpContext.Session.SetString("fido2.options", JsonConvert.SerializeObject(aoptions));

            return Json(aoptions);
        }

        [HttpPost]
        [Route("/makeAssertion")]
        public JsonResult MakeAssertion([FromBody] AuthenticatorAssertionRawResponse r)
        {
            var json = HttpContext.Session.GetString("fido2.options");
            var origChallenge = JsonConvert.DeserializeObject<AssertionOptions>(json);

            // todo: Fetch creds for the user from database.
            var jsonCreds = HttpContext.Session.GetString("fido2.creds");
            var creds = JsonConvert.DeserializeObject<AttestationVerificationData>(jsonCreds);

            byte[] existingPublicKey = creds.PublicKey; // todo: read from database.
            uint storedSignatureCounter = 0; // todo: read from database.

            var requestTokenBindingId = Request.HttpContext.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            var res = _lib.MakeAssertion(r, origChallenge, storedSignatureCounter, existingPublicKey, requestTokenBindingId, (x) => true, (x) => true);
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


        /**
         * 
         * 
         * 
         * CONFORMANCE TESTING ENDPOINTS
         * 
         * 
         * 
         */
        private static CredentialCreateOptions CONFORMANCE_TESTING_PREV_ATT_OPTIONS;
        private static AssertionOptions CONFORMANCE_TESTING_PREV_ASRT_OPTIONS;
        private static Fido2NetLib.Fido2.CredentialMakeResult CONFORMANCE_TESTING_STORED_CREDENTIALS;

        [HttpPost]
        [Route("/attestation/options")]
        public JsonResult MakeCredentialOptionsTest([FromBody] OptionArgsDto opts)
        {
            var user = new User
            {
                DisplayName = opts.DisplayName,
                Id = Base64Url.Decode(opts.Username),
                Name = opts.Username
            };
            var attType = opts.Attestation;

            var x = new AuthenticatorSelection();
            x.UserVerification = UserVerificationRequirement.Discouraged;

            List<PublicKeyCredentialDescriptor> excludeCredentials = null;

            if (CONFORMANCE_TESTING_PREV_ATT_OPTIONS != null)
            {
                var origChallange = CONFORMANCE_TESTING_PREV_ATT_OPTIONS;

                // exclude existing credentials
                // todo: move this to callback?
                // note: Not sure how moving this to callback would simply?
                if (user.Id.SequenceEqual(origChallange.User.Id))
                {
                    if (CONFORMANCE_TESTING_STORED_CREDENTIALS != null)
                    {
                        excludeCredentials = new List<PublicKeyCredentialDescriptor>() {
                            new PublicKeyCredentialDescriptor(CONFORMANCE_TESTING_STORED_CREDENTIALS.Result.CredentialId)
                        };
                    }
                }
            }

            var challenge = _lib.RequestNewCredential(user, opts.AuthenticatorSelection, excludeCredentials, attType);
            CONFORMANCE_TESTING_PREV_ATT_OPTIONS = challenge;

            return Json(challenge);
        }

        [HttpPost]
        [Route("/attestation/result")]
        public JsonResult MakeCredentialResultTest([FromBody] AuthenticatorAttestationRawResponse bodyRes)
        {
            var origChallenge = CONFORMANCE_TESTING_PREV_ATT_OPTIONS;

            var requestTokenBindingId = Request.HttpContext.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            var res = _lib.MakeNewCredential(bodyRes, origChallenge, requestTokenBindingId, (x) => true);

            CONFORMANCE_TESTING_STORED_CREDENTIALS = res;
            return Json(res);
        }

        [HttpPost]
        [Route("/assertion/options")]
        public JsonResult AssertionOptionsTest([FromBody] TEST_AssertionClientOptions assertionClientOptions)
        {
            // todo: Fetch creds for the user from database.

            var creds = CONFORMANCE_TESTING_STORED_CREDENTIALS;
            var allowedCreds = new List<PublicKeyCredentialDescriptor>();
            if (creds != null)
            {
                allowedCreds.Add(new PublicKeyCredentialDescriptor(creds.Result.CredentialId));
            }

            var aoptions = _lib.GetAssertion(new User()
            {
                Id = Encoding.UTF8.GetBytes("1"),
                Name = assertionClientOptions.Username,
                DisplayName = "Display " + assertionClientOptions.Username
            },
            allowedCreds,
            assertionClientOptions.UserVerification
            );

            CONFORMANCE_TESTING_PREV_ASRT_OPTIONS = aoptions;

            return Json(aoptions);
        }

        [HttpPost]
        [Route("/assertion/result")]
        public JsonResult MakeAssertionTest([FromBody] AuthenticatorAssertionRawResponse r)
        {
            var origChallenge = CONFORMANCE_TESTING_PREV_ASRT_OPTIONS;

            // todo: Fetch creds for the user from database.
            var creds = CONFORMANCE_TESTING_STORED_CREDENTIALS;

            byte[] existingPublicKey = creds.Result.PublicKey; // todo: read from database.
            uint storedSignatureCounter = 0; // todo: read from database.

            var requestTokenBindingId = Request.HttpContext.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            var res = _lib.MakeAssertion(r, origChallenge, storedSignatureCounter, existingPublicKey, requestTokenBindingId, (x) => true, (x) => true);
            var res2 = new
            {
                status = "ok",
                errormessage = "",
                res
            };
            return Json(res2);
        }

        /// <summary>
        /// For testing
        /// </summary>
        public class TEST_AssertionClientOptions
        {
            public string Username { get; set; }
            public UserVerificationRequirement UserVerification { get; set; }
        }

        public class OptionArgsDto
        {
            public string DisplayName { get; set; }
            public string Username { get; set; }
            public string Attestation { get; set; }
            public AuthenticatorSelection AuthenticatorSelection { get; set; }
        }
    }
}
