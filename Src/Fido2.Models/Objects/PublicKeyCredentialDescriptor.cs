using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// This object contains the attributes that are specified by a caller when referring to a public key credential as an input parameter to the create() or get() methods. It mirrors the fields of the PublicKeyCredential object returned by the latter methods.
    /// Lazy implementation of https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
    /// todo: Should add validation of values as specified in spec
    /// </summary>
    public class PublicKeyCredentialDescriptor
    {
        public PublicKeyCredentialDescriptor(byte[] credentialId)
        {
            Id = credentialId;
        }

        public PublicKeyCredentialDescriptor()
        {

        }

        /// <summary>
        /// This member contains the type of the public key credential the caller is referring to.
        /// </summary>
        [JsonPropertyName("type")]
        public PublicKeyCredentialType? Type { get; set; } = PublicKeyCredentialType.PublicKey;

        /// <summary>
        /// This member contains the credential ID of the public key credential the caller is referring to.
        /// </summary>
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("id")]
        public byte[] Id { get; set; }

        /// <summary>
        /// This OPTIONAL member contains a hint as to how the client might communicate with the managing authenticator of the public key credential the caller is referring to.
        /// </summary>
        [JsonPropertyName("transports")]
        public AuthenticatorTransport[] Transports { get; set; }
    };
}
