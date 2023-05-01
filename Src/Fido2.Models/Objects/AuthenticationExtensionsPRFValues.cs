using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// 
/// </summary>
public sealed class AuthenticationExtensionsPRFValues
{
    /// <summary>
    /// 
    /// </summary>
    [JsonPropertyName("first")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] First { get; set; }
    /// <summary>
    /// 
    /// </summary>
    [JsonPropertyName("second")]
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public byte[] Second { get; set; }
}

