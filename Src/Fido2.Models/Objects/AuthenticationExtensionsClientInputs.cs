using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// This is a dictionary containing the client extension output values for zero or more WebAuthn Extensions
    /// </summary>
    public class AuthenticationExtensionsClientInputs
    {
        /// <summary>
        /// This extension allows for passing of conformance tests
        /// </summary>
        [JsonProperty("example.extension", NullValueHandling = NullValueHandling.Ignore)]
        public object Example { get; set; }
        /// <summary>
        /// This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO JavaScript APIs to request an assertion.
        /// https://www.w3.org/TR/webauthn/#sctn-appid-extension
        /// </summary>
        [JsonProperty("appid", NullValueHandling = NullValueHandling.Ignore)]
        public string AppID { get; set; }
        /// <summary>
        /// This extension allows a WebAuthn Relying Party to guide the selection of the authenticator that will be leveraged when creating the credential. It is intended primarily for Relying Parties that wish to tightly control the experience around credential creation.
        /// https://www.w3.org/TR/webauthn/#sctn-authenticator-selection-extension
        /// </summary>
        [JsonProperty("authnSel", NullValueHandling = NullValueHandling.Ignore)]
        public byte[][] AuthenticatorSelection { get; set; }
        /// <summary>
        /// This extension enables the WebAuthn Relying Party to determine which extensions the authenticator supports.
        /// https://www.w3.org/TR/webauthn/#sctn-supported-extensions-extension
        /// </summary>
        [JsonProperty("exts", NullValueHandling = NullValueHandling.Ignore)]
        public bool? Extensions { get; set; }
        /// <summary>
        /// This extension enables use of a user verification method.
        /// https://www.w3.org/TR/webauthn/#sctn-uvm-extension
        /// </summary>
        [JsonProperty("uvm", NullValueHandling = NullValueHandling.Ignore)]
        public bool? UserVerificationMethod { get; set; }
    }
}

