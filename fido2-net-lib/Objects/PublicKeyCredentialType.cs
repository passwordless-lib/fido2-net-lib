using System.Runtime.Serialization;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// PublicKeyCredentialType.
    /// https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype
    /// </summary>
    public enum PublicKeyCredentialType
    {
        [EnumMember(Value = "public-key")]
        PublicKey
    }
}
