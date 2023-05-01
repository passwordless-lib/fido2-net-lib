using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// 
/// </summary>
public sealed class AuthenticationExtensionsPRFOutputs
{
    /// <summary>
    /// 
    /// </summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }
    /// <summary>
    /// 
    /// </summary>
    [JsonPropertyName("results")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsPRFValues Results { get; set; }
}
