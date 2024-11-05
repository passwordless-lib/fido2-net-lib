#nullable enable

using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// Evaluated PRF values.
/// </summary>
public sealed class AuthenticationExtensionsPRFValues
{
    /// <summary>
    /// salt1 value to the PRF evaluation.
    /// </summary>
    [JsonPropertyName("first")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public required byte[] First { get; set; }

    /// <summary>
    /// salt2 value to the PRF evaluation.
    /// </summary>
    [JsonPropertyName("second")]
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public byte[]? Second { get; set; }
}

