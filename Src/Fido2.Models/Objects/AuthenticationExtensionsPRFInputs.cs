using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// 
/// </summary>
public sealed class AuthenticationExtensionsPRFInputs
{
    /// <summary>
    /// 
    /// </summary>
    [JsonPropertyName("eval")]
    public AuthenticationExtensionsPRFValues Eval { get; set; }
    /// <summary>
    /// 
    /// </summary>
    [JsonPropertyName("evalByCredential")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public KeyValuePair<string, AuthenticationExtensionsPRFValues>? EvalByCredential { get; set; }
}
