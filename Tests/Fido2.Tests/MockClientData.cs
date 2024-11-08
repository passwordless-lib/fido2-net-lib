using System.Text.Json.Serialization;

namespace Fido2NetLib;

public sealed class MockClientData
{
    [JsonPropertyName("type")]
    public required string Type { get; set; }

    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("challenge")]
    public required byte[] Challenge { get; set; }

    [JsonPropertyName("origin")]
    public required string Origin { get; set; }
}
