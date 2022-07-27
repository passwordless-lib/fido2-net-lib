using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// This is a dictionary containing the client extension output values for zero or more WebAuthn Extensions
    /// </summary>
    public sealed class AuthenticationExtensionsClientInputs
    {
#nullable enable
        /// <summary>
        /// This extension allows for passing of conformance tests
        /// </summary>
        [JsonPropertyName("example.extension.bool")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public object? Example { get; set; }

        /// <summary>
        /// This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO JavaScript APIs to request an assertion.
        /// https://www.w3.org/TR/webauthn/#sctn-appid-extension
        /// </summary>
        [JsonPropertyName("appid")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? AppID { get; set; }

        /// <summary>
        /// This extension enables use of a user verification method.
        /// https://www.w3.org/TR/webauthn/#sctn-uvm-extension
        /// </summary>
        [JsonPropertyName("uvm")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public bool? UserVerificationMethod { get; set; }
#nullable disable
    }
}

