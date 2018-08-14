using System.Linq;
using System.Text;
using Newtonsoft.Json;

namespace fido2NetLib
{
    /// <summary>
    /// Base class for responses sent by the Authenticator Client
    /// </summary>
    public class AuthenticatorResponse
    {

        protected AuthenticatorResponse(byte[] clientDataJson)
        {
            var stringx = Encoding.UTF8.GetString(clientDataJson);
            var response = Newtonsoft.Json.JsonConvert.DeserializeObject<AuthenticatorResponse>(stringx);

            Type = response.Type;
            Challenge = response.Challenge;
            Origin = response.Origin;
            TokenBinding = response.TokenBinding;

        }

        [JsonConstructor]
        private AuthenticatorResponse()
        {

        }

        public string Type { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Challenge { get; set; }
        public string Origin { get; set; }

        public TokenBindingDto TokenBinding { get; set; }

        // todo: add TokenBinding https://www.w3.org/TR/webauthn/#dictdef-tokenbinding

        protected void BaseVerify(string expectedOrigin, byte[] originalChallenge, byte[] requestTokenBindingId)
        {
            // verify challenge is same
            if (!Challenge.SequenceEqual(originalChallenge)) throw new Fido2VerificationException();

            if (Origin != expectedOrigin) throw new Fido2VerificationException();

            if (Type != "webauthn.create" && Type != "webauthn.get") throw new Fido2VerificationException();

            if (TokenBinding != null)
            {
                TokenBinding.Verify(requestTokenBindingId);
            }
        }
    }
}
