using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects
{
    public class AuthenticatorBiometricPerfBounds
    {
        [JsonPropertyName("FAR")]
        public float FAR { get; set; }
        [JsonPropertyName("FRR")]
        public float FRR { get; set; }
    }
}

