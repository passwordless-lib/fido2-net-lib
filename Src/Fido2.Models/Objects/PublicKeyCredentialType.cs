using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// PublicKeyCredentialType.
/// https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype
/// </summary>
[JsonConverter(typeof(FidoEnumConverter<PublicKeyCredentialType>))]
public enum PublicKeyCredentialType
{
    [EnumMember(Value = "public-key")]
    PublicKey,

    [EnumMember(Value = "invalid")]
    Invalid
}
