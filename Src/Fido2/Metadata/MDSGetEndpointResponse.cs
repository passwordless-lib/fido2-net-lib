#nullable disable

using System.Text.Json.Serialization;

namespace Fido2NetLib;

public sealed class MDSGetEndpointResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; }

    [JsonPropertyName("result")]
    public string[] Result { get; set; }
}
