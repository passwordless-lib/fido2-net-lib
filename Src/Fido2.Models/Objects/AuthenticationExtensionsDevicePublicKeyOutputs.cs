#nullable enable

namespace Fido2NetLib.Objects;

using System.Text.Json.Serialization;

[method: JsonConstructor]
public sealed class AuthenticationExtensionsDevicePublicKeyOutputs(
    byte[] authenticatorOutput,
    byte[] signature)
{
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("authenticatorOutput")]
    public byte[] AuthenticatorOutput { get; } = authenticatorOutput;

    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("signature")]
    public byte[] Signature { get; } = signature;
}
