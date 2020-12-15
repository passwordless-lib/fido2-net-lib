using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects
{
    public class TxAuthGenericArg
    {
        [JsonPropertyName("contentType")]
        public string ContentType { get; set; }
        [JsonPropertyName("content")]
        public byte[] Content { get; set; }
    }
}

