#nullable enable

namespace Fido2NetLib.Objects;

using System.Text.Json.Serialization;

public sealed class AuthenticationExtensionsDevicePublicKeyOutputs
{
    [JsonConstructor]
    public AuthenticationExtensionsDevicePublicKeyOutputs(byte[] authenticatorOutput, byte[] signature)
    {
        AuthenticatorOutput = authenticatorOutput;
        Signature = signature;
    }

    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("authenticatorOutput")]
    public byte[] AuthenticatorOutput { get; }

    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("signature")]
    public byte[] Signature { get; }
}
