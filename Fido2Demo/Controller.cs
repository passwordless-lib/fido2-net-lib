using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using fido2NetLib;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Fido2Demo
{
    [Route("api/[controller]")]
    public class MyController : Controller
    {
        // todo: Add proper config
        private Fido2NetLib _lib = new Fido2NetLib(new Fido2NetLib.Configuration
        {
            ServerDomain = "localhost",
            Origin = "https://localhost:44329"
        });

        [HttpPost]
        [Route("/makeCredentialOptions")]
        public JsonResult MakeCredentialOptions([FromForm] string username, [FromForm] string attType)
        {
            var user = new User
            {
                DisplayName = "Default value",
                Name = username,
                Id = "1"
            };

            var challenge = _lib.RequestNewCredential(user, attType);
            HttpContext.Session.SetString("fido2.challenge", JsonConvert.SerializeObject(challenge));

            return Json(challenge);
        }

        [HttpPost]
        [Route("/makeCredential")]
        public Fido2NetLib.CredentialMakeResult MakeCredential()
        {

            // work around failing modelbinding
            // todo: solve why ModelState is invalid (causing modelbind to fail)
            string body;
            using (StreamReader reader = new StreamReader(Request.Body, Encoding.UTF8))
            {
                body = reader.ReadToEnd();
            }

            var bodyRes = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(body);

            var json = HttpContext.Session.GetString("fido2.challenge");
            var origChallenge = JsonConvert.DeserializeObject<CredentialCreateOptions>(json);

            var res = _lib.MakeNewCredential(bodyRes, origChallenge);

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
            var allowedCreds = new List<PublicKeyCredentialDescriptor>() {
                    new PublicKeyCredentialDescriptor()
                    {
                        Id = creds.CredentialId,
                        Type = "public-key"
                    }
                };

            var aoptions = _lib.GetAssertion(new User()
            {
                Id = "1",
                Name = "anders"
            },
            allowedCreds
            );

            HttpContext.Session.SetString("fido2.options", JsonConvert.SerializeObject(aoptions));

            return Json(aoptions);
        }

        [HttpPost]
        [Route("/makeAssertion")]
        public JsonResult MakeAssertion([FromBody] AuthenticatorAssertionRawResponse r)
        {

            //// work around failing modelbinding
            //var x = ModelState.IsValid;
            //string body;
            //using (StreamReader reader = new StreamReader(Request.Body, Encoding.UTF8))
            //{
            //    body = reader.ReadToEnd();
            //}

            //if (r is null)
            //{
            //    throw new Exception("what?");
            //}
            //var bodyRes = JsonConvert.DeserializeObject<AuthenticatorAssertionRawResponse>(body);

            var json = HttpContext.Session.GetString("fido2.options");
            var origChallenge = JsonConvert.DeserializeObject<AssertionOptions>(json);

            // todo: Fetch creds for the user from database.
            var jsonCreds = HttpContext.Session.GetString("fido2.creds");
            var creds = JsonConvert.DeserializeObject<AttestationVerificationData>(jsonCreds);

            byte[] existingPublicKey = creds.PublicKey; // todo: read from database.
            var res = _lib.MakeAssertion(r, origChallenge, existingPublicKey);
            return Json(res);

        }
    }
}
