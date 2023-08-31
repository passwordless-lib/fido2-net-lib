using System.Text.Json.Serialization;

namespace Fido2NetLib;

public abstract class Fido2ResponseBase
{
    [JsonPropertyName("status")]
    public string Status { get; set; }

#nullable enable

    [JsonPropertyName("errorMessage")]
    public string? ErrorMessage { get; set; }
}
