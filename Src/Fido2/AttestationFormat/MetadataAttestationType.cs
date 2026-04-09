using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

#if NET9_0_OR_GREATER
[JsonConverter(typeof(JsonStringEnumConverter<MetadataAttestationType>))]
#else
[JsonConverter(typeof(FidoEnumConverter<MetadataAttestationType>))]
#endif
internal enum MetadataAttestationType
{
    /// <summary>
    /// Indicates full basic attestation, based on an attestation private key shared among a class of authenticators (e.g. same model).
    /// Authenticators must provide its attestation signature during the registration process for the same reason.
    /// The attestation trust anchor is shared with FIDO Servers out of band (as part of the Metadata).
    /// This sharing process shouldt be done according to [UAFMetadataService].
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("basic_full")]
#else
    [EnumMember(Value = "basic_full")]
#endif
    ATTESTATION_BASIC_FULL = 0x3e07,

    /// <summary>
    /// Just syntactically a Basic Attestation.
    /// The attestation object self-signed, i.e. it is signed using the UAuth.priv key, i.e. the key corresponding to the UAuth.pub key included in the attestation object.
    /// As a consequence it does not provide a cryptographic proof of the security characteristics.
    /// But it is the best thing we can do if the authenticator is not able to have an attestation private key.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("basic_surrogate")]
#else
    [EnumMember(Value = "basic_surrogate")]
#endif
    ATTESTATION_BASIC_SURROGATE = 0x3e08,

    /// <summary>
    /// Indicates use of elliptic curve based direct anonymous attestation as defined in [FIDOEcdaaAlgorithm].
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("ecdaa")]
#else
    [EnumMember(Value = "ecdaa")]
#endif
    [Fido2Standard(Optional = true)]
    ATTESTATION_ECDAA = 0x3e09,

    /// <summary>
    /// Indicates PrivacyCA attestation as defined in [TCG-CMCProfile-AIKCertEnroll].
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("attca")]
#else
    [EnumMember(Value = "attca")]
#endif
    [Fido2Standard(Optional = true)]
    ATTESTATION_PRIVACY_CA = 0x3e10,

    /// <summary>
    /// Anonymization CA (AnonCA)
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("anonca")]
#else
    [EnumMember(Value = "anonca")]
#endif
    ATTESTATION_ANONCA = 0x3e0c,

#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("none")]
#else
    [EnumMember(Value = "none")]
#endif
    ATTESTATION_NONE = 0x3e0b
}
