using System.Text.Json.Serialization;

namespace Fido2NetLib;

public sealed class MDSGetEndpointResponse
{
    [JsonConstructor]
    public MDSGetEndpointResponse(string status, string[] result)
    {
        Status = status;
        Result = result;
    }

    [JsonPropertyName("status")]
    public string Status { get; }

    [JsonPropertyName("result")]
    public string[] Result { get; }
}
