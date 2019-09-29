using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class MetadataTOCPayload
    {
        [JsonProperty("legalHeader")]
        public string LegalHeader { get; set; }
        [JsonProperty("no", Required = Required.Always)]
        public int Number { get; set; }
        [JsonProperty("nextUpdate", Required = Required.Always)]
        public string NextUpdate { get; set; }
        [JsonProperty("entries", Required = Required.Always)]
        public MetadataTOCPayloadEntry[] Entries { get; set; }
    }
}
