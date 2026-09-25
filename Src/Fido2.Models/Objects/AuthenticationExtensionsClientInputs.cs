#nullable disable

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
    /// https://www.w3.org/TR/webauthn-3/#sctn-appid-extension
    /// </summary>
    [JsonPropertyName("appid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string AppID { get; set; }

    /// <summary>
    /// This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO JavaScript APIs
    /// to prevent re-registration of an existing U2F credential by excluding it, using the same AppID, during a registration ceremony.
    /// https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension
    /// </summary>
    [JsonPropertyName("appidExclude")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
    public string AppIDExclude { get; set; }

    /// <summary>
    /// This extension enables the WebAuthn Relying Party to determine which extensions the authenticator
    /// supports. Defined by WebAuthn Level 1 and removed in Level 2.
    /// https://www.w3.org/TR/webauthn-1/#sctn-supported-extensions-extension
    /// </summary>
    [Obsolete("The exts (supported extensions) extension was defined by WebAuthn Level 1 and removed in Level 2; no client will populate it. This member will be removed in a future major version.")]
    [JsonPropertyName("exts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Extensions { get; set; }

    /// <summary>
    /// This extension enables use of a user verification method.
    /// https://www.w3.org/TR/webauthn-2/#sctn-uvm-extension
    /// </summary>
    [Obsolete("The uvm extension was removed in WebAuthn Level 3 and no client will populate it; see Level 2 if you still need it. This member will be removed in a future major version.")]
    [JsonPropertyName("uvm")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? UserVerificationMethod { private get; set; }

#nullable enable

    /// <summary>
    /// This client registration extension facilitates reporting certain credential properties known by the client to the requesting WebAuthn Relying Party upon creation of a public key credential source as a result of a registration ceremony.
    /// </summary>
    [JsonPropertyName("credProps")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? CredProps { get; set; }

    /// <summary>
    /// This extension allows a Relying Party to evaluate outputs from a pseudo-random function (PRF) associated with a credential.
    /// https://www.w3.org/TR/webauthn-3/#prf-extension
    /// </summary>
    [JsonPropertyName("prf")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsPRFInputs? PRF { get; set; }

    /// <summary>
    /// This client registration extension and authentication extension allows a Relying Party to store opaque data associated with a credential.
    /// https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension
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

    /// <summary>
    /// A small amount of opaque data, in a Relying Party specific format, to store with the credential. The
    /// authenticator supports at least 32 bytes; its <c>maxCredBlobLength</c> in <c>authenticatorGetInfo</c>
    /// reports the actual limit, and a client silently ignores a larger value.
    /// </summary>
    /// <remarks>
    /// Valid only during registration; use <see cref="GetCredBlob"/> to read it back. Anything sensitive stored
    /// here needs <see cref="CredentialProtectionPolicy"/> set to
    /// <see cref="Objects.CredentialProtectionPolicy.UserVerificationRequired"/> together with
    /// <see cref="EnforceCredentialProtectionPolicy"/>, because the blob is otherwise readable without user
    /// verification.
    /// <para>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credBlob-extension"/>
    /// </para>
    /// </remarks>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("credBlob")]
    public byte[]? CredBlob { get; set; }

    /// <summary>
    /// Requests the <c>credBlob</c> stored with the credential. Valid only during assertion.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credBlob-extension"/>
    /// </remarks>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("getCredBlob")]
    public bool? GetCredBlob { get; set; }

    /// <summary>
    /// Requests the authenticator's current PIN complexity policy, so that an organization issuing configured
    /// authenticators can check the policy still meets its requirements. Valid only during registration; the
    /// answer arrives in the authenticator extension outputs rather than the client extension outputs. New in
    /// CTAP 2.3.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-pincomplexitypolicy-extension"/>
    /// </remarks>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("pinComplexityPolicy")]
    public bool? PinComplexityPolicy { get; set; }

    /// <summary>
    /// Requests the minimum PIN length the authenticator enforces. Valid only during registration.
    /// </summary>
    /// <remarks>
    /// A CTAP2 authenticator extension exposed to Relying Parties through WebAuthn's generic extension
    /// passthrough; it is not itself a WebAuthn-defined extension. The authenticator answers only a Relying
    /// Party it has been configured to answer.
    /// <para>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-minpinlength-extension"/>
    /// </para>
    /// </remarks>
    [JsonPropertyName("minPinLength")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? MinPinLength { get; set; }
}

