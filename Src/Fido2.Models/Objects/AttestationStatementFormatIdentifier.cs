using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The attestation statement format identifier in WebAuthn specifies the format of the attestation statement that is used to attest to the authenticity of a credential created by a WebAuthn authenticator.
/// https://www.iana.org/assignments/webauthn/webauthn.xhtml
/// </summary>
[JsonConverter(typeof(FidoEnumConverter<AttestationStatementFormatIdentifier>))]
public enum AttestationStatementFormatIdentifier
{
    /// <summary>
    /// The "packed" attestation statement format is a WebAuthn-optimized format for attestation. It uses a very compact but still extensible encoding method. This format is implementable by authenticators with limited resources (e.g., secure elements).
    /// </summary>
    [EnumMember(Value = "packed")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("packed")]
#endif
    Packed,

    /// <summary>
    /// The "TPM" attestation statement format returns an attestation statement in the same format as the packed attestation statement format, although the rawData and signature fields are computed differently.
    /// </summary>
    [EnumMember(Value = "tpm")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("tpm")]
#endif
    Tpm,

    /// <summary>
    /// Platform authenticators on versions "N", and later, may provide this proprietary "hardware attestation" statement.
    /// </summary>
    [EnumMember(Value = "android-key")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("android-key")]
#endif
    AndroidKey,

    /// <summary>
    /// Android-based platform authenticators MAY produce an attestation statement based on the Android SafetyNet API.
    /// </summary>
    [EnumMember(Value = "android-safetynet")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("android-safetynet")]
#endif
    AndroidSafetyNet,

    /// <summary>
    /// Used with FIDO U2F authenticators.
    /// </summary>
    [EnumMember(Value = "fido-u2f")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("fido-u2f")]
#endif
    FidoU2f,

    /// <summary>
    /// Used with Apple devices' platform authenticators.
    /// </summary>
    [EnumMember(Value = "apple")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("apple")]
#endif
    Apple,

    /// <summary>
    /// Used to replace any authenticator-provided attestation statement when a WebAuthn Relying Party indicates it does not wish to receive attestation information.
    /// </summary>
    [EnumMember(Value = "none")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("none")]
#endif
    None
}

