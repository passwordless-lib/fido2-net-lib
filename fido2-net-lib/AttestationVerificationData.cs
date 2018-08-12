using Newtonsoft.Json;

namespace fido2NetLib
{
    /// <summary>
    /// Holds parsed credential data
    /// </summary>
    public class AttestationVerificationData
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] PublicKey { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] CredentialId { get; set; }
    }
}
