using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class StatusReport
    {
        [JsonProperty("status", Required = Required.Always)]
        public AuthenticatorStatus Status { get; set; }
        [JsonProperty("effectiveDate")]
        public string EffectiveDate { get; set; }
        [JsonProperty("certificate")]
        public string Certificate { get; set; }
        [JsonProperty("url")]
        public string Url { get; set; }
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
