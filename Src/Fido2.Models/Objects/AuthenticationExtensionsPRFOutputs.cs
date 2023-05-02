using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// This is a dictionary containing the PRF extension output values
/// </summary>
public sealed class AuthenticationExtensionsPRFOutputs
{
    /// <summary>
    /// If PRFs are available for use with the created credential.
    /// </summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }
    /// <summary>
    /// The results of evaluating the PRF inputs.
    /// </summary>
    [JsonPropertyName("results")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsPRFValues Results { get; set; }
}
