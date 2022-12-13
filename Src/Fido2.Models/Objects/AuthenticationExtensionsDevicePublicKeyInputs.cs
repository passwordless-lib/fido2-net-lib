using System;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects
{
    public sealed class AuthenticationExtensionsDevicePublicKeyInputs
    {
        [JsonPropertyName("attestation")]
        public string Attestation { get; set; } = "none";

        [JsonPropertyName("attestationFormats")]
        public string[] AttestationFormats { get; set; } = Array.Empty<string>();
    }
}
