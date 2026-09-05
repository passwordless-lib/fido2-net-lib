#nullable enable

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Describes supported versions, extensions, AAGUID of the device and its capabilities.
/// The information is the same reported by an authenticator when invoking the CTAP2
/// "authenticatorGetInfo" method.
/// </summary>
/// <remarks>
/// This field is present in the <see cref="MetadataStatement"/> for FIDO2 authenticators that
/// natively support FIDO CTAP. Platform API-only authenticators should not provide this field.
/// UAF and U2F authenticators do not support it.
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html"/>
/// </remarks>
public sealed class AuthenticatorGetInfo
{
    /// <summary>
    /// List of supported versions, e.g. "U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1", "FIDO_2_3".
    /// </summary>
    [JsonPropertyName("versions")]
    public string[]? Versions { get; set; }

    /// <summary>
    /// List of supported extension identifiers.
    /// </summary>
    [JsonPropertyName("extensions")]
    public string[]? Extensions { get; set; }

    /// <summary>
    /// The claimed AAGUID, encoded as specified in [WebAuthn].
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("aaguid")]
    public byte[]? AAGUID { get; set; }

    /// <summary>
    /// List of supported option identifiers to their current values (e.g. "rk", "up", "uv", "plat", "clientPin").
    /// </summary>
    [JsonPropertyName("options")]
    public Dictionary<string, bool>? Options { get; set; }

    /// <summary>
    /// Maximum message size supported by the authenticator.
    /// </summary>
    [JsonPropertyName("maxMsgSize")]
    public int? MaxMsgSize { get; set; }

    /// <summary>
    /// List of supported PIN/UV Auth Protocol versions, in decreasing order of authenticator preference.
    /// </summary>
    [JsonPropertyName("pinUvAuthProtocols")]
    public int[]? PinUvAuthProtocols { get; set; }

    /// <summary>
    /// Maximum number of credentials supported in a credentialID list at a time by the authenticator.
    /// </summary>
    [JsonPropertyName("maxCredentialCountInList")]
    public int? MaxCredentialCountInList { get; set; }

    /// <summary>
    /// Maximum credential ID length supported by the authenticator.
    /// </summary>
    [JsonPropertyName("maxCredentialIdLength")]
    public int? MaxCredentialIdLength { get; set; }

    /// <summary>
    /// List of supported transports, using values from the AuthenticatorTransport enum in [WebAuthn].
    /// </summary>
    [JsonPropertyName("transports")]
    public string[]? Transports { get; set; }

    /// <summary>
    /// List of supported algorithms for credential generation, ordered by decreasing authenticator preference.
    /// </summary>
    [JsonPropertyName("algorithms")]
    public PubKeyCredParam[]? Algorithms { get; set; }

    /// <summary>
    /// The maximum size, in bytes, of the serialized large-blob array that this authenticator can store.
    /// </summary>
    [JsonPropertyName("maxSerializedLargeBlobArray")]
    public int? MaxSerializedLargeBlobArray { get; set; }

    /// <summary>
    /// If present and set to true, certain PIN/UV commands will return errors until after the PIN has been changed.
    /// </summary>
    [JsonPropertyName("forcePINChange")]
    public bool? ForcePINChange { get; set; }

    /// <summary>
    /// The current minimum PIN length, in Unicode code points, the authenticator enforces for ClientPIN.
    /// </summary>
    [JsonPropertyName("minPINLength")]
    public int? MinPINLength { get; set; }

    /// <summary>
    /// Indicates the firmware version of the authenticator model identified by AAGUID.
    /// </summary>
    [JsonPropertyName("firmwareVersion")]
    public int? FirmwareVersion { get; set; }

    /// <summary>
    /// Maximum credBlob length in bytes supported by the authenticator.
    /// </summary>
    [JsonPropertyName("maxCredBlobLength")]
    public int? MaxCredBlobLength { get; set; }

    /// <summary>
    /// The max number of RP IDs that the authenticator can set via the setMinPINLength subcommand.
    /// </summary>
    [JsonPropertyName("maxRPIDsForSetMinPINLength")]
    public int? MaxRPIDsForSetMinPINLength { get; set; }

    /// <summary>
    /// The preferred number of invocations of the getPinUvAuthTokenUsingUvWithPermissions subcommand
    /// the platform may attempt before falling back to the ClientPIN.
    /// </summary>
    [JsonPropertyName("preferredPlatformUvAttempts")]
    public int? PreferredPlatformUvAttempts { get; set; }

    /// <summary>
    /// The user verification modality supported by the authenticator, as a bit flag combination.
    /// </summary>
    [JsonPropertyName("uvModality")]
    public int? UvModality { get; set; }

    /// <summary>
    /// A hint to the platform with additional information about certifications that the authenticator has received.
    /// </summary>
    [JsonPropertyName("certifications")]
    public Dictionary<string, int>? Certifications { get; set; }

    /// <summary>
    /// If present, the number of additional discoverable credentials that can be stored.
    /// </summary>
    [JsonPropertyName("remainingDiscoverableCredentials")]
    public int? RemainingDiscoverableCredentials { get; set; }

    /// <summary>
    /// List of authenticatorConfig vendorPrototype subcommand identifiers.
    /// </summary>
    [JsonPropertyName("vendorPrototypeConfigCommands")]
    public int[]? VendorPrototypeConfigCommands { get; set; }

    /// <summary>
    /// List of supported attestation statement formats, in decreasing order of authenticator preference.
    /// </summary>
    [JsonPropertyName("attestationFormats")]
    public string[]? AttestationFormats { get; set; }
}
