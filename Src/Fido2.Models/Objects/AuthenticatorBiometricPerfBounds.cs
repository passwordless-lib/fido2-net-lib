using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{
    public class AuthenticatorBiometricPerfBounds
    {
        [JsonProperty("FAR", NullValueHandling = NullValueHandling.Ignore)]
        public float FAR { get; set; }
        [JsonProperty("FRR", NullValueHandling = NullValueHandling.Ignore)]
        public float FRR { get; set; }
    }
}

