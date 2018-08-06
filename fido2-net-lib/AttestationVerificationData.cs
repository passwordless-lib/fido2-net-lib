using Newtonsoft.Json;

namespace fido2NetLib
{
    public class AttestationVerificationData
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] PublicKey { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] CredentialId { get; set; }
    }
}
