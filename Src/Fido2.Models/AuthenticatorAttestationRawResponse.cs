using System.Text.Json;
using System.Text.Json.Serialization;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    public class AuthenticatorAttestationRawResponse
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("id")]
        public byte[] Id { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("rawId")]
        public byte[] RawId { get; set; }

        [JsonPropertyName("type")]
        public PublicKeyCredentialType? Type { get; set; }

        [JsonPropertyName("response")]
        public ResponseData Response { get; set; }

        [JsonPropertyName("extensions")]
        public AuthenticationExtensionsClientOutputs Extensions { get; set; }

        public class ResponseData
        {
            [JsonConverter(typeof(Base64UrlConverter))]
            [JsonPropertyName("attestationObject")]
            public byte[] AttestationObject { get; set; }
            [JsonConverter(typeof(Base64UrlConverter))]
            [JsonPropertyName("clientDataJSON")]
            public byte[] ClientDataJson { get; set; }
        }
    }
}
