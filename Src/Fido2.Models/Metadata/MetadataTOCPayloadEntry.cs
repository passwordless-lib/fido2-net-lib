using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class MetadataTOCPayloadEntry
    {
        [JsonProperty("aaid")]
        public string Aaid { get; set; }
        [JsonProperty("aaguid")]
        public string AaGuid { get; set; }
        [JsonProperty("attestationCertificateKeyIdentifiers")]
        public string[] AttestationCertificateKeyIdentifiers { get; set; }
        [JsonProperty("hash")]
        public string Hash { get; set; }
        [JsonProperty("url")]
        public string Url { get; set; }
        [JsonProperty("biometricStatusReports")]
        public BiometricStatusReport[] BiometricStatusReports { get; set; }
        [JsonProperty("statusReports", Required = Required.Always)]
        public StatusReport[] StatusReports { get; set; }
        [JsonProperty("timeOfLastStatusChange")]
        public string TimeOfLastStatusChange { get; set; }
        [JsonProperty("rogueListURL")]
        public string RogueListURL { get; set; }
        [JsonProperty("rogueListHash")]
        public string RogueListHash { get; set; }
        [JsonProperty("metadataStatement")]
        //[JsonConverter(typeof(Base64UrlConverter))]
        public MetadataStatement MetadataStatement { get; set; }
    }

}
