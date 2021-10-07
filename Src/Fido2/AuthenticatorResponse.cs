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
            if (clientDataJson is null)
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

            if (response is null)
                throw new Fido2VerificationException("Deserialized authenticator response cannot be null");
            Type = response.Type;
            Challenge = response.Challenge;
            Origin = response.Origin;
        }

#nullable disable
        [JsonConstructor]
        private AuthenticatorResponse()
        {

        }
#nullable enable

        public string Type { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Challenge { get; set; }
        public string Origin { get; set; }

        // todo: add TokenBinding https://www.w3.org/TR/webauthn/#dictdef-tokenbinding

        protected void BaseVerify(string expectedOrigin, byte[] originalChallenge, byte[] requestTokenBindingId)
        {
            if (Type is not "webauthn.create" && Type is not "webauthn.get")
                throw new Fido2VerificationException($"Type not equal to 'webauthn.create' or 'webauthn.get'. Was: '{Type}'");

            if (Challenge is null)
                throw new Fido2VerificationException("Challenge cannot be null");

            // 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call
            if (!Challenge.SequenceEqual(originalChallenge))
                throw new Fido2VerificationException("Challenge not equal to original challenge");

            var fullyQualifiedOrigin = FullyQualifiedOrigin(Origin);
            var fullyQualifiedExpectedOrigin = FullyQualifiedOrigin(expectedOrigin);

            // 5. Verify that the value of C.origin matches the Relying Party's origin.
            if (!string.Equals(fullyQualifiedOrigin, fullyQualifiedExpectedOrigin, StringComparison.OrdinalIgnoreCase))
                throw new Fido2VerificationException($"Fully qualified origin {fullyQualifiedOrigin} of {Origin} not equal to fully qualified original origin {fullyQualifiedExpectedOrigin} of {expectedOrigin}");

        }

        private string FullyQualifiedOrigin(string origin)
        {
            var uri = new Uri(origin);

            if (UriHostNameType.Unknown != uri.HostNameType)
                return uri.IsDefaultPort ? $"{uri.Scheme}://{uri.Host}" : $"{uri.Scheme}://{uri.Host}:{uri.Port}";

            return origin;
        }
    }
}
