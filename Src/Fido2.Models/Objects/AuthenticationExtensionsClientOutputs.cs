using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

public class AuthenticationExtensionsClientOutputs
{
    /// <summary>
    /// This extension allows for passing of conformance tests
    /// </summary>
    [JsonPropertyName("example.extension.bool")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object Example { get; set; }

#nullable enable

    /// <summary>
    /// This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO JavaScript APIs to request an assertion.
    /// https://www.w3.org/TR/webauthn/#sctn-appid-extension
    /// </summary>
    [JsonPropertyName("appid")]
    public bool AppID { get; set; }
    
    /// <summary>
    /// This extension allows a WebAuthn Relying Party to guide the selection of the authenticator that will be leveraged when creating the credential. It is intended primarily for Relying Parties that wish to tightly control the experience around credential creation.
    /// https://www.w3.org/TR/webauthn/#sctn-authenticator-selection-extension
    /// </summary>
    [JsonPropertyName("authnSel")]
    public bool AuthenticatorSelection { get; set; }

    /// <summary>
    /// This extension enables the WebAuthn Relying Party to determine which extensions the authenticator supports.
    /// https://www.w3.org/TR/webauthn/#sctn-supported-extensions-extension
    /// </summary>
    [JsonPropertyName("exts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? Extensions { get; set; }

    /// <summary>
    /// This extension enables use of a user verification method.
    /// https://www.w3.org/TR/webauthn/#sctn-uvm-extension
    /// </summary>
    [JsonPropertyName("uvm")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ulong[][]? UserVerificationMethod { get; set; }

    /// <summary>
    /// This authenticator registration extension and authentication extension provides a Relying Party with a "device continuity" signal for backup eligible credentials.
    /// https://w3c.github.io/webauthn/#sctn-device-publickey-extension
    /// </summary>
    [JsonPropertyName("devicePubKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsDevicePublicKeyOutputs? DevicePubKey { get; set; }

    /// <summary>
    /// This client registration extension facilitates reporting certain credential properties known by the client to the requesting WebAuthn Relying Party upon creation of a public key credential source as a result of a registration ceremony.
    /// </summary>
    [JsonPropertyName("credProps")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CredentialPropertiesOutput? CredProps { get; set; }
    
    /// <summary>
    /// This extension allows a Relying Party to evaluate outputs from a pseudo-random function (PRF) associated with a credential.
    /// https://w3c.github.io/webauthn/#prf-extension
    /// </summary>
    [JsonPropertyName("prf")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsPRFOutputs? PRF { get; set; }
}