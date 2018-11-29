using System.Linq;
using System.Text;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// Base class for responses sent by the Authenticator Client
    /// </summary>
    public class AuthenticatorResponse
    {

        protected AuthenticatorResponse(byte[] clientDataJson)
        {
            if (null == clientDataJson) throw new Fido2VerificationException("clientDataJson cannot be null");
            var stringx = Encoding.UTF8.GetString(clientDataJson);

            AuthenticatorResponse response = null;
            try
            {
                response = Newtonsoft.Json.JsonConvert.DeserializeObject<AuthenticatorResponse>(stringx);
            }
            catch (System.Exception e)//Newtonsoft.Json.JsonReaderException) 
            {
                if (e is JsonReaderException || e is JsonSerializationException)
                {
                    throw new Fido2VerificationException("Malformed clientDataJson");
                }
                else throw;
            }

            if (null == response) throw new Fido2VerificationException("Deserialized authenticator response cannot be null");
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
            if (null == Challenge) throw new Fido2VerificationException("Challenge cannot be null");
            // verify challenge is same
            if (!Challenge.SequenceEqual(originalChallenge)) throw new Fido2VerificationException("Challenge not equal to original challenge");

            if (Origin != expectedOrigin) throw new Fido2VerificationException("Origin not equal to original origin");

            if (Type != "webauthn.create" && Type != "webauthn.get") throw new Fido2VerificationException($"Type not equal to 'webauthn.create' or 'webauthn.get'. Was: '{Type}'");

            if (TokenBinding != null)
            {
                TokenBinding.Verify(requestTokenBindingId);
            }
        }
    }
}
