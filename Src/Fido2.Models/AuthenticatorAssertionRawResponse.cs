using System.Text.Json;
using System.Text.Json.Serialization;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    /// <summary>
    /// Transport class for AssertionResponse
    /// </summary>
    public class AuthenticatorAssertionRawResponse
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Id { get; set; }

        // might be wrong to base64url encode this...
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] RawId { get; set; }

        public AssertionResponse Response { get; set; }

        public PublicKeyCredentialType? Type { get; set; }

        public AuthenticationExtensionsClientOutputs Extensions { get; set; }

        public class AssertionResponse
        {
            [JsonConverter(typeof(Base64UrlConverter))]
            public byte[] AuthenticatorData { get; set; }

            [JsonConverter(typeof(Base64UrlConverter))]
            public byte[] Signature { get; set; }

            [JsonPropertyName("clientDataJson")]
            [JsonConverter(typeof(Base64UrlConverter))]
            public byte[] ClientDataJson { get; set; }

            [JsonPropertyName("userHandle")]
            [JsonConverter(typeof(NullableBase64UrlConverter))]
            public byte[] UserHandle { get; set; }
        }
    }
}
