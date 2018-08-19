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

            var challenge = _lib.RequestNewCredential(user, AuthenticatorSelection.Default, null, AttestationConveyancePreference.Parse(attType));
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
            var res = _lib.MakeNewCredential(bodyRes, origChallenge, (x) => true, requestTokenBindingId);

            HttpContext.Session.SetString("fido2.creds", JsonConvert.SerializeObject(res.Result));
            return res;
        }

        [HttpPost]
        [Route("/assertionOptions")]
        public JsonResult AssertionOptions(string username)
        {
            // todo: Fetch creds for the user from database.
            var jsonCreds = HttpContext.Session.GetString("fido2.creds");
            var creds = JsonConvert.DeserializeObject<AttestationVerificationSuccess>(jsonCreds);

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

            var aoptions = _lib.GetAssertionOptions(
                allowedCredentials,
                UserVerificationRequirement.Preferred
            );

            HttpContext.Session.SetString("fido2.options", JsonConvert.SerializeObject(aoptions));

            return Json(aoptions);
        }

        [HttpPost]
        [Route("/makeAssertion")]
        public JsonResult MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse)
        {
            var json = HttpContext.Session.GetString("fido2.options");
            var originalChallenge = JsonConvert.DeserializeObject<AssertionOptions>(json);

            // todo: Fetch creds for the user from database.
            var jsonCreds = HttpContext.Session.GetString("fido2.creds");
            var creds = JsonConvert.DeserializeObject<AttestationVerificationSuccess>(jsonCreds);

            byte[] existingPublicKey = creds.PublicKey; // todo: read from database.
            uint storedSignatureCounter = 0; // todo: read from database.

            var requestTokenBindingId = Request.HttpContext.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            var res = _lib.MakeAssertion(clientResponse, originalChallenge, existingPublicKey, storedSignatureCounter, (x) => true, requestTokenBindingId);
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
