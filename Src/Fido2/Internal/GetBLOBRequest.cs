using System.Text.Json.Serialization;

namespace Fido2NetLib.Internal;

[method: JsonConstructor]
public readonly struct GetBLOBRequest(string endpoint)
{
    [JsonPropertyName("endpoint")]
    public string Endpoint { get; } = endpoint;
}
