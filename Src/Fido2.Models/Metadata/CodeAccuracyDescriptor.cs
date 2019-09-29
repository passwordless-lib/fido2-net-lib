using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class CodeAccuracyDescriptor
    {
        [JsonProperty("base", Required = Required.Always)]
        public ushort Base { get; set; }
        [JsonProperty("minLength", Required = Required.Always)]
        public ushort MinLength { get; set; }
        [JsonProperty("maxRetries")]
        public ushort MaxRetries { get; set; }
        [JsonProperty("blockSlowdown")]
        public ushort BlockSlowdown { get; set; }
    }
}
