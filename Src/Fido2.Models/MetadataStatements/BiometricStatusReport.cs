using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class BiometricStatusReport
    {
        [JsonProperty("certLevel", Required = Required.Always)]
        public ushort CertLevel { get; set; }
        [JsonProperty("modality", Required = Required.Always)]
        public ulong Modality { get; set; }
        [JsonProperty("effectiveDate")]
        public string EffectiveDate { get; set; }
        [JsonProperty("certificationDescriptor")]
        public string CertificationDescriptor { get; set; }
        [JsonProperty("certificateNumber")]
        public string CertificateNumber { get; set; }
        [JsonProperty("certificationPolicyVersion")]
        public string CertificationPolicyVersion { get; set; }
        [JsonProperty("certificationRequirementsVersion")]
        public string CertificationRequirementsVersion { get; set; }
    }
}
