using System.Linq;
using System.Text;
using Newtonsoft.Json;

namespace fido2NetLib
{
    public class AuthenticatorResponse
    {

        protected AuthenticatorResponse(byte[] clientDataJson)
        {
            var stringx = Encoding.UTF8.GetString(clientDataJson);
            var response = Newtonsoft.Json.JsonConvert.DeserializeObject<AuthenticatorResponse>(stringx);

            this.Type = response.Type;
            this.Challenge = response.Challenge;
            this.Origin = response.Origin;

        }

        [JsonConstructor]
        private AuthenticatorResponse()
        {

        }

        public string Type { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Challenge { get; set; }
        public string Origin { get; set; }

        // todo: add TokenBinding https://www.w3.org/TR/webauthn/#dictdef-tokenbinding

        protected void BaseVerify(string expectedOrigin, byte[] originalChallenge)
        {
            // verify challenge is same
            if (!this.Challenge.SequenceEqual(originalChallenge)) throw new Fido2VerificationException();

            if (this.Origin != expectedOrigin) throw new Fido2VerificationException();

            if (this.Type != "webauthn.create" && this.Type != "webauthn.get") throw new Fido2VerificationException();
            
        }
    }
}
