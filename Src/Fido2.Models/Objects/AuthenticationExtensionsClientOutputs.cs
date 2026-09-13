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
    /// https://www.w3.org/TR/webauthn-3/#sctn-appid-extension
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
    /// This extension enables the WebAuthn Relying Party to determine which extensions the authenticator
    /// supports. Defined by WebAuthn Level 1 and removed in Level 2.
    /// https://www.w3.org/TR/webauthn-1/#sctn-supported-extensions-extension
    /// </summary>
    [Obsolete("The exts (supported extensions) extension was defined by WebAuthn Level 1 and removed in Level 2; no client will populate it. This member will be removed in a future major version.")]
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
    /// https://www.w3.org/TR/webauthn-3/#prf-extension
    /// </summary>
    [JsonPropertyName("prf")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsPRFOutputs? PRF { get; set; }

    /// <summary>
    /// This client registration extension and authentication extension allows a Relying Party to store opaque data associated with a credential.
    /// https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension
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

    /// <summary>
    /// The minimum PIN length, in Unicode code points, the authenticator enforces for the created credential.
    /// Returned only when the Relying Party requested the <c>minPinLength</c> extension and the authenticator
    /// is configured to disclose it to that Relying Party.
    /// </summary>
    /// <remarks>
    /// A CTAP2 authenticator extension exposed to Relying Parties through WebAuthn's generic extension
    /// passthrough; it is not itself a WebAuthn-defined extension.
    /// <para>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-minpinlength-extension"/>
    /// </para>
    /// </remarks>
    [JsonPropertyName("minPinLength")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? MinPinLength { get; set; }

    /// <summary>
    /// The Secure Payment Confirmation extension's output: the browser-bound key's signature, when there is one.
    /// https://www.w3.org/TR/secure-payment-confirmation/#sctn-payment-extension-registration
    /// </summary>
    [JsonPropertyName("payment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsPaymentOutputs? Payment { get; set; }
}
