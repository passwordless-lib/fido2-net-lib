﻿using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

public class AuthenticationExtensionsClientOutputs
{
    /// <summary>
    /// This extension allows for passing of conformance tests
    /// </summary>
    [JsonPropertyName("example.extension")]
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
}
