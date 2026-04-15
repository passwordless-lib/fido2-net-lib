using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The attestation statement format identifier in WebAuthn specifies the format of the attestation statement that is used to attest to the authenticity of a credential created by a WebAuthn authenticator.
/// https://www.iana.org/assignments/webauthn/webauthn.xhtml
/// </summary>
#if NET9_0_OR_GREATER
[JsonConverter(typeof(JsonStringEnumConverter<AttestationStatementFormatIdentifier>))]
#else
[JsonConverter(typeof(FidoEnumConverter<AttestationStatementFormatIdentifier>))]
#endif
public enum AttestationStatementFormatIdentifier
{
    /// <summary>
    /// The "packed" attestation statement format is a WebAuthn-optimized format for attestation. It uses a very compact but still extensible encoding method. This format is implementable by authenticators with limited resources (e.g., secure elements).
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("packed")]
#endif
    [EnumMember(Value = "packed")]
    Packed,

    /// <summary>
    /// The "TPM" attestation statement format returns an attestation statement in the same format as the packed attestation statement format, although the rawData and signature fields are computed differently.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("tpm")]
#endif
    [EnumMember(Value = "tpm")]
    Tpm,

    /// <summary>
    /// Platform authenticators on versions "N", and later, may provide this proprietary "hardware attestation" statement.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("android-key")]
#endif
    [EnumMember(Value = "android-key")]
    AndroidKey,

    /// <summary>
    /// Android-based platform authenticators MAY produce an attestation statement based on the Android SafetyNet API.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("android-safetynet")]
#endif
    [EnumMember(Value = "android-safetynet")]
    AndroidSafetyNet,

    /// <summary>
    /// Used with FIDO U2F authenticators.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("fido-u2f")]
#endif
    [EnumMember(Value = "fido-u2f")]
    FidoU2f,

    /// <summary>
    /// Used with Apple devices' platform authenticators.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("apple")]
#endif
    [EnumMember(Value = "apple")]
    Apple,

    /// <summary>
    /// Used to replace any authenticator-provided attestation statement when a WebAuthn Relying Party indicates it does not wish to receive attestation information.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("none")]
#endif
    [EnumMember(Value = "none")]
    None
}

