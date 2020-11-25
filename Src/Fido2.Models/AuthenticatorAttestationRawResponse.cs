using Newtonsoft.Json;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    public class AuthenticatorAttestationRawResponse
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Id { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] RawId { get; set; }

        public PublicKeyCredentialType? Type { get; set; }

        public ResponseData Response { get; set; }

        public AuthenticationExtensionsClientOutputs Extensions { get; set; }

        public class ResponseData
        {
            [JsonConverter(typeof(Base64UrlConverter))]
            public byte[] AttestationObject { get; set; }
            [JsonConverter(typeof(Base64UrlConverter))]
            public byte[] ClientDataJson { get; set; }
        }
    }
}
