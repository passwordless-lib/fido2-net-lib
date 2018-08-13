using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using fido2NetLib;
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

        public MyController(IConfiguration config)
        {
            _lib = new Fido2NetLib(new Fido2NetLib.Configuration
            {
                ServerDomain = config["fido2:serverDomain"],
                ServerName = "Fido2 test",
                Origin = config["fido2:origin"]
            });
        }
        // todo: Add proper config
        private Fido2NetLib _lib;

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

            var challenge = _lib.RequestNewCredential(user, attType);
            HttpContext.Session.SetString("fido2.challenge", JsonConvert.SerializeObject(challenge));

            return Json(challenge);
        }

        [HttpPost]
        [Route("/makeCredential")]
        public Fido2NetLib.CredentialMakeResult MakeCredential([FromBody] AuthenticatorAttestationRawResponse bodyRes)
        {
            var json = HttpContext.Session.GetString("fido2.challenge");
            var origChallenge = JsonConvert.DeserializeObject<CredentialCreateOptions>(json);

            var requestTokenBindingId = Request.HttpContext.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            var res = _lib.MakeNewCredential(bodyRes, origChallenge, requestTokenBindingId, (crendialId, user) => true);

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
                Id = Encoding.UTF8.GetBytes("1"),
                Name = username,
                DisplayName = "Display " + username
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
            var json = HttpContext.Session.GetString("fido2.options");
            var origChallenge = JsonConvert.DeserializeObject<AssertionOptions>(json);

            // todo: Fetch creds for the user from database.
            var jsonCreds = HttpContext.Session.GetString("fido2.creds");
            var creds = JsonConvert.DeserializeObject<AttestationVerificationData>(jsonCreds);

            byte[] existingPublicKey = creds.PublicKey; // todo: read from database.
            uint storedSignatureCounter = 0; // todo: read from database.

            var requestTokenBindingId = Request.HttpContext.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            var res = _lib.MakeAssertion(r, origChallenge, storedSignatureCounter, existingPublicKey, requestTokenBindingId, (userhandle, credentialId) => true, null);
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
