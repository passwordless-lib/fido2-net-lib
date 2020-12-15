using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// Holds parsed credential data
    /// </summary>
    public class AttestationVerificationSuccess : AssertionVerificationResult
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] PublicKey { get; set; }

        public Fido2User User { get; set; }
        public string CredType { get; set; }
        public System.Guid Aaguid { get; set; }
    }
}
