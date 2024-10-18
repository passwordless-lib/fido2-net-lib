using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// CredentialProtectionPolicy
/// https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-credProtect-extension
/// </summary>
[JsonConverter(typeof(FidoEnumConverter<CredentialProtectionPolicy>))]
public enum CredentialProtectionPolicy
{
    /// <summary>
    /// This reflects "FIDO_2_0" semantics. In this configuration, performing some form of user verification is OPTIONAL with or without credentialID list.
    /// This is the default state of the credential if the extension is not specified
    /// </summary>
    [EnumMember(Value = "userVerificationOptional")]
    UserVerificationOptional = 0x01,

    /// <summary>
    /// In this configuration, credential is discovered only when its credentialID is provided by the platform or when some form of user verification is performed.
    /// </summary>
    [EnumMember(Value = "userVerificationOptionalWithCredentialIDList")]
    UserVerificationOptionalWithCredentialIdList = 0x02,

    /// <summary>
    /// TThis reflects that discovery and usage of the credential MUST be preceded by some form of user verification.
    /// </summary>
    [EnumMember(Value = "userVerificationRequired")]
    UserVerificationRequired = 0x03
}
