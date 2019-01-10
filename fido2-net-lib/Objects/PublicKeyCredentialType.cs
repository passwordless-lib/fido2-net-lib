using System.Runtime.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// PublicKeyCredentialType.
    /// https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum PublicKeyCredentialType
    {
        [EnumMember(Value = "public-key")]
        PublicKey
    }
}
