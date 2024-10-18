using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

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
    public bool? Example { get; set; }

    /// <summary>
    /// This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO JavaScript APIs to request an assertion.
    /// https://www.w3.org/TR/webauthn/#sctn-appid-extension
    /// </summary>
    [JsonPropertyName("appid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
    public string AppID { get; set; }

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
    /// TODO: Remove this completely as it's removed in L3
    /// </summary>
    [JsonPropertyName("uvm")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? UserVerificationMethod { private get; set; }

#nullable enable
    /// <summary>
    /// This extension enables use of a user verification method.
    /// https://www.w3.org/TR/webauthn/#sctn-uvm-extension
    /// </summary>
    [JsonPropertyName("devicePubKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsDevicePublicKeyInputs? DevicePubKey { get; set; }

    /// <summary>
    /// This client registration extension facilitates reporting certain credential properties known by the client to the requesting WebAuthn Relying Party upon creation of a public key credential source as a result of a registration ceremony.
    /// </summary>
    [JsonPropertyName("credProps")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? CredProps { get; set; }

    /// <summary>
    /// This extension allows a Relying Party to evaluate outputs from a pseudo-random function (PRF) associated with a credential.
    /// https://w3c.github.io/webauthn/#prf-extension
    /// </summary>
    [JsonPropertyName("prf")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsPRFInputs? PRF { get; set; }

    /// <summary>
    /// This client registration extension and authentication extension allows a Relying Party to store opaque data associated with a credential.
    /// https://w3c.github.io/webauthn/#sctn-large-blob-extension
    /// </summary>
    [JsonPropertyName("largeBlob")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsLargeBlobInputs? LargeBlob { get; set; }

    /// <summary>
    /// This registration extension allows relying parties to specify a credential protection policy when creating a credential.
    /// Additionally, authenticators MAY choose to establish a default credential protection policy greater than <c>UserVerificationOptional</c> (the lowest level)
    /// and unilaterally enforce such policy. Authenticators not supporting some form of user verification MUST NOT support this extension.
    /// Authenticators supporting some form of user verification MUST process this extension and persist the credProtect value with the credential,
    /// even if the authenticator is not protected by some form of user verification at the time.
    /// https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-credProtect-extension
    /// </summary>
    [JsonPropertyName("credentialProtectionPolicy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CredentialProtectionPolicy? CredentialProtectionPolicy { get; set; }

    /// <summary>
    ///  This controls whether it is better to fail to create a credential rather than ignore the protection policy.
    ///  When true, and <c>CredentialProtectionPolicy</c>'s value is
    ///  either <c>UserVerificationOptionalWithCredentialIdList</c> or <c>UserVerificationRequired</c>, the platform
    ///  SHOULD NOT create the credential in a way that does not implement the requested protection policy.
    /// </summary>
    [JsonPropertyName("enforceCredentialProtectionPolicy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? EnforceCredentialProtectionPolicy { get; set; }
}

