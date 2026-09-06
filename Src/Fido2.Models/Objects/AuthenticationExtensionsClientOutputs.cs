using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

public class AuthenticationExtensionsClientOutputs
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
    public bool AppID { get; set; }

    /// <summary>
    /// This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO JavaScript APIs
    /// to prevent re-registration of an existing U2F credential by excluding it, using the same AppID, during a registration ceremony.
    /// https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension
    /// </summary>
    [JsonPropertyName("appidExclude")]
    public bool AppIDExclude { get; set; }

    /// <summary>
    /// This extension enables the WebAuthn Relying Party to determine which extensions the authenticator supports.
    /// https://www.w3.org/TR/webauthn-2/#sctn-supported-extensions-extension
    /// </summary>
    [Obsolete("The exts (supported extensions) extension was removed in WebAuthn Level 3 and no client will populate it. This member will be removed in a future major version.")]
    [JsonPropertyName("exts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? Extensions { get; set; }

    /// <summary>
    /// This extension enables use of a user verification method.
    /// https://www.w3.org/TR/webauthn-2/#sctn-uvm-extension
    /// </summary>
    [Obsolete("The uvm extension was removed in WebAuthn Level 3 and no client will populate it; see Level 2 if you still need it. This member will be removed in a future major version.")]
    [JsonPropertyName("uvm")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ulong[][]? UserVerificationMethod { get; set; }

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

    /// <summary>
    /// This client registration extension and authentication extension allows a Relying Party to store opaque data associated with a credential.
    /// https://w3c.github.io/webauthn/#sctn-large-blob-extension
    /// </summary>
    [JsonPropertyName("largeBlob")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsLargeBlobOutputs? LargeBlob { get; set; }

    /// <summary>
    /// The <c>CredentialProtectionPolicy</c> stored alongside the created credential
    /// https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-credProtect-extension
    /// </summary>
    [JsonPropertyName("credProtect")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CredentialProtectionPolicy? CredProtect { get; set; }

    /// <summary>
    /// The minimum PIN length, in Unicode code points, enforced by the authenticator for the created credential.
    /// Only returned when the Relying Party requested the <c>minPinLength</c> extension and the authenticator/client permit disclosing it.
    /// This is a CTAP2 authenticator extension exposed to Relying Parties via WebAuthn's generic extension
    /// passthrough mechanism; it is not itself a WebAuthn-defined extension.
    /// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-minpinlength-extension
    /// </summary>
    /// <summary>
    /// Whether the authenticator stored the requested <c>credBlob</c>. Registration only; it may be
    /// <see langword="false"/> when the blob exceeded the authenticator's <c>maxCredBlobLength</c> or the
    /// extension is unsupported for non-discoverable credentials.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credBlob-extension"/>
    /// </remarks>
    [JsonPropertyName("credBlob")]
    public bool? CredBlob { get; set; }

    /// <summary>
    /// The <c>credBlob</c> stored with the credential, or empty if the authenticator has none for it. Assertion
    /// only.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credBlob-extension"/>
    /// </remarks>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("getCredBlob")]
    public byte[]? GetCredBlob { get; set; }

    [JsonPropertyName("minPinLength")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? MinPinLength { get; set; }
}
