using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{
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
        /// This extension allows for a simple form of transaction authorization. A Relying Party can specify a prompt string, intended for display on a trusted device on the authenticator.
        /// https://www.w3.org/TR/webauthn/#sctn-simple-txauth-extension
        /// </summary>
        [JsonProperty("txAuthSimple", NullValueHandling = NullValueHandling.Ignore)]
        public string SimpleTransactionAuthorization { get; set; }
        /// <summary>
        /// This extension allows images to be used as transaction authorization prompts as well. This allows authenticators without a font rendering engine to be used and also supports a richer visual appearance.
        /// https://www.w3.org/TR/webauthn/#sctn-generic-txauth-extension
        /// </summary>
        [JsonProperty("txAuthGenericArg", NullValueHandling = NullValueHandling.Ignore)]
        public TxAuthGenericArg GenericTransactionAuthorization { get; set; }
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
        /// This extension enables use of a user verification index.
        /// https://www.w3.org/TR/webauthn/#sctn-uvi-extension
        /// </summary>
        [JsonProperty("uvi", NullValueHandling = NullValueHandling.Ignore)]
        public bool? UserVerificationIndex { get; set; }
        /// <summary>
        /// This extension provides the authenticator's current location to the WebAuthn WebAuthn Relying Party.
        /// https://www.w3.org/TR/webauthn/#sctn-location-extension
        /// </summary>
        [JsonProperty("loc", NullValueHandling = NullValueHandling.Ignore)]
        public bool? Location { get; set; }
        /// <summary>
        /// This extension enables use of a user verification method.
        /// https://www.w3.org/TR/webauthn/#sctn-uvm-extension
        /// </summary>
        [JsonProperty("uvm", NullValueHandling = NullValueHandling.Ignore)]
        public bool? UserVerificationMethod { get; set; }
        /// <summary>
        /// This extension allows WebAuthn Relying Parties to specify the desired performance bounds for selecting biometric authenticators as candidates to be employed in a registration ceremony.
        /// https://www.w3.org/TR/webauthn/#sctn-authenticator-biometric-criteria-extension
        /// </summary>
        [JsonProperty("biometricPerfBounds", NullValueHandling = NullValueHandling.Ignore)]
        public AuthenticatorBiometricPerfBounds BiometricAuthenticatorPerformanceBounds { get; set; }
    }
}

