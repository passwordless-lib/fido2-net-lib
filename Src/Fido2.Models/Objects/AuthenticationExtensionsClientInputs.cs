using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// This is a dictionary containing the client extension output values for zero or more WebAuthn Extensions
    /// </summary>
    public sealed class AuthenticationExtensionsClientInputs
    {
        /// <summary>
        /// This extension allows for passing of conformance tests
        /// </summary>
        [JsonPropertyName("example.extension.bool")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public object Example { get; set; }

        /// <summary>
        /// This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO JavaScript APIs to request an assertion.
        /// https://www.w3.org/TR/webauthn/#sctn-appid-extension
        /// </summary>
        [JsonPropertyName("appid")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string AppID { get; set; }

        /// <summary>
        /// This extension allows a WebAuthn Relying Party to guide the selection of the authenticator that will be leveraged when creating the credential. It is intended primarily for Relying Parties that wish to tightly control the experience around credential creation.
        /// https://www.w3.org/TR/webauthn/#sctn-authenticator-selection-extension
        /// </summary>
        [JsonPropertyName("authnSel")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public byte[][] AuthenticatorSelection { get; set; }

        /// <summary>
        /// This extension enables the WebAuthn Relying Party to determine which extensions the authenticator supports.
        /// https://www.w3.org/TR/webauthn/#sctn-supported-extensions-extension
        /// </summary>
        [JsonPropertyName("exts")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public bool? Extensions { get; set; }

        /// <summary>
        /// This extension enables use of a user verification method.
        /// https://www.w3.org/TR/webauthn/#sctn-uvm-extension
        /// </summary>
        [JsonPropertyName("uvm")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public bool? UserVerificationMethod { get; set; }
    }
}

