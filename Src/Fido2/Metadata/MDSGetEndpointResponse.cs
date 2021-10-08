#nullable disable

using Newtonsoft.Json;

namespace Fido2NetLib
{
    internal sealed class MDSGetEndpointResponse
    {
        [JsonProperty("status", Required = Required.Always)]
        public string Status { get; set; }

        [JsonProperty("result", Required = Required.Always)]
        public string[] Result { get; set; }
    }
}
