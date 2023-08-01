#nullable enable

namespace Fido2NetLib.Objects;

using System.Text.Json.Serialization;

public sealed class AuthenticationExtensionsCredentialPropertiesOutputs
{
    /// <summary>
    /// Whether the credential in question was created as a resident (discoverable) credential
    /// </summary>
    [JsonPropertyName("rk")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? ResidentKey { get; set; }
}
