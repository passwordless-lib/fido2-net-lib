using System.Text.Json.Serialization;

namespace Fido2NetLib.Internal;

public readonly struct GetBLOBRequest
{
    [JsonConstructor]
    public GetBLOBRequest(string endpoint)
    {
        Endpoint = endpoint;
    }

    [JsonPropertyName("endpoint")]
    public string Endpoint { get; }
}
