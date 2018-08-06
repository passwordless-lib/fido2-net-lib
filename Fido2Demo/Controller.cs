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

        public static byte[] StringToByteArray(String hex)
        {
            hex = hex.Replace("-", "");
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }


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
        public Fido2NetLib.CreationResult MakeCredential()
        {

            // work around failing modelbinding
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
            //var credId = "F1-3C-7F-08-3C-A2-29-E0-B4-03-E8-87-34-6E-FC-7F-98-53-10-3A-30-91-75-67-39-7A-D1-D8-AF-87-04-61-87-EF-95-31-85-60-F3-5A-1A-2A-CF-7D-B0-1D-06-B9-69-F9-AB-F4-EC-F3-07-3E-CF-0F-71-E8-84-E8-41-20";
            var allowedCreds = new List<PublicKeyCredentialDescriptor>() {
                    new PublicKeyCredentialDescriptor()
                    {
                        Id = creds.CredentialId,
                        Type = "public-key"
                    }
                };

            // assertion

            var aoptions = _lib.GetAssertion(new User()
            {
                Id = "1",
                Name = "anders"
            },
            allowedCreds
            );

            HttpContext.Session.SetString("fido2.options", JsonConvert.SerializeObject(aoptions));

            return Json(aoptions);
            //var options = _lib.GetAssertion(new User()
            //{
            //    Id = "1",
            //    Name = username
            //});


            //return Json(options);

        }

        [HttpPost]
        [Route("/makeAssertion")]
        public JsonResult MakeAssertion( [FromBody] AuthenticatorAssertionRawResponse r)
        {
            var x = ModelState.IsValid;
          

            // work around failing modelbinding
            string body;
            using (StreamReader reader = new StreamReader(Request.Body, Encoding.UTF8))
            {
                body = reader.ReadToEnd();
            }

            if (r is null)
            {
                throw new Exception("what?");
            }

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

        // GET api/<controller>/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<controller>
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }

        // PUT api/<controller>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/<controller>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }


    }

    public class Createdto
    {
        [JsonProperty(PropertyName = "displayName")]
        public string DisplayName { get; set; }
        public string Username { get; set; }
    }
}
