using System;
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
            if (null == clientDataJson)
                throw new Fido2VerificationException("clientDataJson cannot be null");
            // 1. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON
            var JSONtext = Encoding.UTF8.GetString(clientDataJson);

            // 2. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext
            // Note: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.
            // We call this AuthenticatorResponse
            AuthenticatorResponse response;
            try
            {
                response = JsonConvert.DeserializeObject<AuthenticatorResponse>(JSONtext);
            }
            catch (Exception e) when (e is JsonReaderException || e is JsonSerializationException)
            {
                throw new Fido2VerificationException("Malformed clientDataJson");
            }

            if (null == response)
                throw new Fido2VerificationException("Deserialized authenticator response cannot be null");
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
            if (Type != "webauthn.create" && Type != "webauthn.get")
                throw new Fido2VerificationException($"Type not equal to 'webauthn.create' or 'webauthn.get'. Was: '{Type}'");

            if (null == Challenge)
                throw new Fido2VerificationException("Challenge cannot be null");

            // 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call
            if (!Challenge.SequenceEqual(originalChallenge))
                throw new Fido2VerificationException("Challenge not equal to original challenge");

            // 5. Verify that the value of C.origin matches the Relying Party's origin.
            if (!string.Equals(FullyQualifiedOrigin(this.Origin), expectedOrigin, StringComparison.OrdinalIgnoreCase))
                throw new Fido2VerificationException($"Origin {Origin} not equal to original origin {expectedOrigin}");

            // 6. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained. 
            // If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
            if (TokenBinding != null)
            {
                TokenBinding.Verify(requestTokenBindingId);
            }
        }

        private string FullyQualifiedOrigin(string origin)
        {
            var uri = new Uri(origin);

            return $"{uri.Scheme}://{uri.Host}";
        }
    }
}
