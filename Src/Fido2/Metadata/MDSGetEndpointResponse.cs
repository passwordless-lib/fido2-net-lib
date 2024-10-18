using System.Text.Json.Serialization;

namespace Fido2NetLib;

[method: JsonConstructor]
public sealed class MDSGetEndpointResponse(string status, string[] result)
{
    [JsonPropertyName("status")]
    public string Status { get; } = status;

    [JsonPropertyName("result")]
    public string[] Result { get; } = result;
}
