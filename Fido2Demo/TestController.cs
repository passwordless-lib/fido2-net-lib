using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace Fido2Demo
{
    public class TestController : Controller
    {
        /**
         * 
         * 
         * 
         * CONFORMANCE TESTING ENDPOINTS
         * 
         * 
         * 
         */

        private Fido2NetLib.Fido2 _lib;

        public TestController(IConfiguration config)
        {
            _lib = new Fido2(new Fido2NetLib.Fido2.Configuration
            {
                ServerDomain = config["fido2:serverDomain"],
                ServerName = "Fido2 test",
                Origin = config["fido2:origin"]
            });
        }

        private static CredentialCreateOptions CONFORMANCE_TESTING_PREV_ATT_OPTIONS;
        private static AssertionOptions CONFORMANCE_TESTING_PREV_ASRT_OPTIONS;
        private static Fido2NetLib.Fido2.CredentialMakeResult CONFORMANCE_TESTING_STORED_CREDENTIALS;
        private static Dictionary<string, uint> CONFORMANCE_TESTING_COUNTER = new Dictionary<string, uint>();

        [HttpPost]
        [Route("/attestation/options")]
        public JsonResult MakeCredentialOptionsTest([FromBody] TEST_MakeCredentialParams opts)
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

            var challenge = _lib.RequestNewCredential(user, excludeCredentials, opts.AuthenticatorSelection, attType);
            CONFORMANCE_TESTING_PREV_ATT_OPTIONS = challenge;

            return Json(challenge);
        }

        [HttpPost]
        [Route("/attestation/result")]
        public JsonResult MakeCredentialResultTest([FromBody] AuthenticatorAttestationRawResponse bodyRes)
        {
            var origChallenge = CONFORMANCE_TESTING_PREV_ATT_OPTIONS;

            var requestTokenBindingId = GetTokenBindingId();
            var res = _lib.MakeNewCredential(bodyRes, origChallenge, (x) => true, requestTokenBindingId);

            CONFORMANCE_TESTING_STORED_CREDENTIALS = res;
            CONFORMANCE_TESTING_COUNTER[Base64Url.Encode(res.Result.CredentialId)] = 0;
            return Json(res);
        }

        [HttpPost]
        [Route("/assertion/options")]
        public JsonResult AssertionOptionsTest([FromBody] TEST_AssertionClientParams assertionClientParams)
        {
            // todo: Fetch creds for the user from database.

            var creds = CONFORMANCE_TESTING_STORED_CREDENTIALS;
            var allowedCredentials = new List<PublicKeyCredentialDescriptor>();
            if (creds != null)
            {
                allowedCredentials.Add(new PublicKeyCredentialDescriptor(creds.Result.CredentialId));
            }

            var aoptions = _lib.GetAssertionOptions(
                allowedCredentials,
                assertionClientParams.UserVerification
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

            byte[] existingPublicKey = creds.Result.PublicKey;
            uint storedSignatureCounter = CONFORMANCE_TESTING_COUNTER[Base64Url.Encode(r.Id)];

            var requestTokenBindingId = GetTokenBindingId();
            var res = _lib.MakeAssertion(r, origChallenge, existingPublicKey, storedSignatureCounter, (x) => true, requestTokenBindingId);

            CONFORMANCE_TESTING_COUNTER[Base64Url.Encode(creds.Result.CredentialId)] = res.Counter;

            var res2 = new
            {
                status = "ok",
                errormessage = "",
                res
            };
            return Json(res2);
        }        

        private byte[] GetTokenBindingId()
        {
            return Request.HttpContext.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
        }

        /// <summary>
        /// For testing
        /// </summary>
        public class TEST_AssertionClientParams
        {
            public string Username { get; set; }
            public UserVerificationRequirement UserVerification { get; set; }
        }

        public class TEST_MakeCredentialParams
        {
            public string DisplayName { get; set; }
            public string Username { get; set; }
            public AttestationConveyancePreference Attestation { get; set; }
            public AuthenticatorSelection AuthenticatorSelection { get; set; }
        }
    }
}
