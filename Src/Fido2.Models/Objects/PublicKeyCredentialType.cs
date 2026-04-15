using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// PublicKeyCredentialType.
/// https://www.w3.org/TR/webauthn-2/#enum-credentialType
/// </summary>
#if NET9_0_OR_GREATER
[JsonConverter(typeof(JsonStringEnumConverter<PublicKeyCredentialType>))]
#else
[JsonConverter(typeof(FidoEnumConverter<PublicKeyCredentialType>))]
#endif
public enum PublicKeyCredentialType
{
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("public-key")]
#endif
    [EnumMember(Value = "public-key")]
    PublicKey,

#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("invalid")]
#endif
    [EnumMember(Value = "invalid")]
    Invalid
}
