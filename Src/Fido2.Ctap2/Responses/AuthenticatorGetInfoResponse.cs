using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Response to the authenticatorGetInfo (0x04) command.
/// <para>
/// Member numbering follows §6.4 of the CTAP 2.3 Proposed Standard (2026-02-26).
/// </para>
/// </summary>
public sealed class AuthenticatorGetInfoResponse
{
    /// <summary>
    /// List of supported versions.
    /// <para>
    /// Supported versions are: "FIDO_2_3" for CTAP2.3, "FIDO_2_1" for CTAP2.1, "FIDO_2_0" for CTAP2.0,
    /// "FIDO_2_1_PRE" for CTAP2.1 preview features and "U2F_V2" for CTAP1/U2F authenticators.
    /// </para>
    /// <para>
    /// Note that "FIDO_2_2" was never defined and MUST NOT appear here. This is modelled as an
    /// open-ended list of opaque strings: version identifiers that this library does not recognize are
    /// preserved verbatim rather than rejected, so authenticators reporting future versions still parse.
    /// Callers should test for membership rather than assume a closed set.
    /// </para>
    /// </summary>
    [CborMember(0x01)]
    public string[]? Versions { get; set; }

    /// <summary>
    /// List of supported extensions.
    /// </summary>
    [CborMember(0x02)]
    public string[]? Extensions { get; set; }

    /// <summary>
    /// The claimed AAGUID.
    /// 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in [WebAuthn].
    /// </summary>
    [CborMember(0x03)]
    public byte[]? Aaguid { get; set; }

    /// <summary>
    /// List of supported options.
    /// </summary>
    [CborMember(0x04)]
    public CborMap? Options { get; set; }

    /// <summary>
    /// Maximum message size supported by the authenticator.
    /// </summary>
    [CborMember(0x05)]
    public int? MaxMsgSize { get; set; }

    /// <summary>
    /// List of supported PIN/UV auth protocol versions, in decreasing order of authenticator preference.
    /// <para>Named "pinUvAuthProtocols" in CTAP 2.1 and later.</para>
    /// </summary>
    [CborMember(0x06)]
    public int[]? PinProtocols { get; set; }

    /// <summary>
    /// Maximum number of credentials supported in credentialID list at a time by the authenticator.
    /// </summary>
    [CborMember(0x07)]
    public int? MaxCredentialCountInList { get; set; }

    /// <summary>
    /// Maximum Credential ID Length supported by the authenticator.
    /// </summary>
    [CborMember(0x08)]
    public int? MaxCredentialIdLength { get; set; }

    /// <summary>
    /// List of supported transports.
    /// Values are taken from the AuthenticatorTransport enum in [WebAuthn].
    /// </summary>
    [CborMember(0x09)]
    public string[]? Transports { get; set; }

    /// <summary>
    /// List of supported algorithms for credential generation, as specified in [WebAuthn].
    /// The array is ordered by decreasing preference of the authenticator.
    /// </summary>
    [CborMember(0x0A)]
    public PubKeyCredParam[]? Algorithms { get; set; }

    /// <summary>
    /// The maximum size, in bytes, of the serialized large-blob array that this authenticator can store.
    /// </summary>
    [CborMember(0x0B)]
    public int? MaxSerializedLargeBlobArray { get; set; }

    /// <summary>
    /// If present and set to true, certain PIN commands will return errors until after the PIN has been changed.
    /// </summary>
    [CborMember(0x0C)]
    public bool? ForcePinChange { get; set; }

    /// <summary>
    /// The current minimum PIN length, in Unicode code points, the authenticator enforces for ClientPIN.
    /// </summary>
    [CborMember(0x0D)]
    public int? MinPinLength { get; set; }

    /// <summary>
    /// Indicates the firmware version of the authenticator model identified by AAGUID.
    /// </summary>
    [CborMember(0x0E)]
    public int? FirmwareVersion { get; set; }

    /// <summary>
    /// Maximum credBlob length in bytes supported by the authenticator.
    /// </summary>
    [CborMember(0x0F)]
    public int? MaxCredBlobLength { get; set; }

    /// <summary>
    /// This specifies the max number of RP IDs that authenticator can set via setMinPINLength subcommand.
    /// </summary>
    [CborMember(0x10)]
    public int? MaxRpidsForSetMinPinLength { get; set; }

    /// <summary>
    /// This specifies the preferred number of invocations of the getPinUvAuthTokenUsingUvWithPermissions
    /// subCommand the platform may attempt before falling back to the ClientPIN.
    /// </summary>
    [CborMember(0x11)]
    public int? PreferredPlatformUvAttempts { get; set; }

    /// <summary>
    /// This specifies the user verification modality supported by the authenticator via
    /// authenticatorClientPIN's getPinUvAuthTokenUsingUvWithPermissions subcommand.
    /// </summary>
    [CborMember(0x12)]
    public int? UvModality { get; set; }

    /// <summary>
    /// Provides a hint to the platform with additional information about certifications that the
    /// authenticator has received.
    /// </summary>
    [CborMember(0x13)]
    public CborMap? Certifications { get; set; }

    /// <summary>
    /// If present, the number of additional discoverable credentials that can be stored.
    /// </summary>
    [CborMember(0x14)]
    public int? RemainingDiscoverableCredentials { get; set; }

    /// <summary>
    /// List of authenticatorConfig vendorPrototype subcommand identifiers.
    /// </summary>
    [CborMember(0x15)]
    public int[]? VendorPrototypeConfigCommands { get; set; }

    /// <summary>
    /// List of supported attestation formats, in decreasing order of authenticator preference.
    /// </summary>
    [CborMember(0x16)]
    public string[]? AttestationFormats { get; set; }

    /// <summary>
    /// If present, the number of internal User Verification operations since the last PIN entry.
    /// </summary>
    [CborMember(0x17)]
    public int? UvCountSinceLastPinEntry { get; set; }

    /// <summary>
    /// If present and set to true, a touch of at least 5 seconds is required for reset.
    /// <para>New in CTAP 2.2.</para>
    /// </summary>
    [CborMember(0x18)]
    public bool? LongTouchForReset { get; set; }

    /// <summary>
    /// An encrypted identifier that lets a platform recognize a specific authenticator across calls.
    /// <para>
    /// The value is <c>iv || ct</c>, where <c>ct</c> is the AES-128-CBC encryption of the 128-bit device
    /// identifier under a key derived via HKDF-SHA-256 from the persistent PIN/UV auth token. The IV is
    /// regenerated for every getInfo response, so the raw bytes differ between calls and MUST NOT be
    /// compared directly for equality.
    /// </para>
    /// <para>New in CTAP 2.2.</para>
    /// </summary>
    [CborMember(0x19)]
    public byte[]? EncIdentifier { get; set; }

    /// <summary>
    /// List of transports that support the reset command.
    /// Values are taken from the AuthenticatorTransport enum in [WebAuthn].
    /// <para>New in CTAP 2.2.</para>
    /// </summary>
    [CborMember(0x1A)]
    public string[]? TransportsForReset { get; set; }

    /// <summary>
    /// If present and set to true, the authenticator enforces a PIN complexity policy.
    /// <para>New in CTAP 2.2.</para>
    /// </summary>
    [CborMember(0x1B)]
    public bool? PinComplexityPolicy { get; set; }

    /// <summary>
    /// A URL describing the enforced PIN complexity policy.
    /// <para>Encoded as a CBOR byte string rather than a text string, per §6.4.</para>
    /// <para>New in CTAP 2.2.</para>
    /// </summary>
    [CborMember(0x1C)]
    public byte[]? PinComplexityPolicyUrl { get; set; }

    /// <summary>
    /// The maximum PIN length, in Unicode code points, supported by the authenticator.
    /// <para>New in CTAP 2.2.</para>
    /// </summary>
    [CborMember(0x1D)]
    public int? MaxPinLength { get; set; }

    /// <summary>
    /// An opaque value that changes whenever the state of the authenticator's credential store changes,
    /// letting a platform detect that its cached view is stale.
    /// <para>New in CTAP 2.3.</para>
    /// </summary>
    [CborMember(0x1E)]
    public byte[]? EncCredStoreState { get; set; }

    /// <summary>
    /// List of supported authenticatorConfig command identifiers.
    /// <para>New in CTAP 2.3.</para>
    /// </summary>
    [CborMember(0x1F)]
    public int[]? AuthenticatorConfigCommands { get; set; }

    /// <summary>
    /// Parses an <see cref="AuthenticatorGetInfoResponse"/> from its CBOR representation.
    /// <para>
    /// Members this library does not model are ignored rather than treated as an error, so responses
    /// from authenticators implementing a newer revision of CTAP still parse.
    /// </para>
    /// </summary>
    public static AuthenticatorGetInfoResponse FromCborObject(CborObject cbor)
    {
        var result = new AuthenticatorGetInfoResponse();

        foreach (var (key, value) in (CborMap)cbor)
        {
            switch ((int)key)
            {
                #pragma warning disable format
                case 0x01: result.Versions                         = CborHelper.ToStringArray(value);       break;
                case 0x02: result.Extensions                       = CborHelper.ToStringArray(value);       break;
                case 0x03: result.Aaguid                           = (byte[])value;                         break;
                case 0x04: result.Options                          = (CborMap)value;                        break;
                case 0x05: result.MaxMsgSize                       = (int)value;                            break;
                case 0x06: result.PinProtocols                     = CborHelper.ToInt32Array(value);        break;
                case 0x07: result.MaxCredentialCountInList         = (int)value;                            break;
                case 0x08: result.MaxCredentialIdLength            = (int)value;                            break;
                case 0x09: result.Transports                       = CborHelper.ToStringArray(value);       break;
                case 0x0A: result.Algorithms                       = CborHelper.ToPubKeyCredParams(value);  break;
                case 0x0B: result.MaxSerializedLargeBlobArray      = (int)value;                            break;
                case 0x0C: result.ForcePinChange                   = (bool)value;                           break;
                case 0x0D: result.MinPinLength                     = (int)value;                            break;
                case 0x0E: result.FirmwareVersion                  = (int)value;                            break;
                case 0x0F: result.MaxCredBlobLength                = (int)value;                            break;
                case 0x10: result.MaxRpidsForSetMinPinLength       = (int)value;                            break;
                case 0x11: result.PreferredPlatformUvAttempts      = (int)value;                            break;
                case 0x12: result.UvModality                       = (int)value;                            break;
                case 0x13: result.Certifications                   = (CborMap)value;                        break;
                case 0x14: result.RemainingDiscoverableCredentials = (int)value;                            break;
                case 0x15: result.VendorPrototypeConfigCommands    = CborHelper.ToInt32Array(value);        break;
                case 0x16: result.AttestationFormats               = CborHelper.ToStringArray(value);       break;
                case 0x17: result.UvCountSinceLastPinEntry         = (int)value;                            break;
                case 0x18: result.LongTouchForReset                = (bool)value;                           break;
                case 0x19: result.EncIdentifier                    = (byte[])value;                         break;
                case 0x1A: result.TransportsForReset               = CborHelper.ToStringArray(value);       break;
                case 0x1B: result.PinComplexityPolicy              = (bool)value;                           break;
                case 0x1C: result.PinComplexityPolicyUrl           = (byte[])value;                         break;
                case 0x1D: result.MaxPinLength                     = (int)value;                            break;
                case 0x1E: result.EncCredStoreState                = (byte[])value;                         break;
                case 0x1F: result.AuthenticatorConfigCommands      = CborHelper.ToInt32Array(value);        break;
                #pragma warning restore format
            }
        }

        return result;
    }
}
