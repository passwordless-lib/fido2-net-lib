using Newtonsoft.Json;

namespace Fido2NetLib
{
    public enum AuthenticatorStatus
    {
        NOT_FIDO_CERTIFIED,
        FIDO_CERTIFIED,
        USER_VERIFICATION_BYPASS,
        ATTESTATION_KEY_COMPROMISE,
        USER_KEY_REMOTE_COMPROMISE,
        USER_KEY_PHYSICAL_COMPROMISE,
        UPDATE_AVAILABLE,
        REVOKED,
        SELF_ASSERTION_SUBMITTED,
        FIDO_CERTIFIED_L1,
        FIDO_CERTIFIED_L1plus,
        FIDO_CERTIFIED_L2,
        FIDO_CERTIFIED_L2plus,
        FIDO_CERTIFIED_L3,
        FIDO_CERTIFIED_L3plus
    };
    public class StatusReport
    {
        [JsonProperty("status")]
        public AuthenticatorStatus Status { get; set; }
        [JsonProperty("effictiveDate")]
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
    public class BiometricStatusReport
    {
        [JsonProperty("certLevel")]
        public ushort CertLevel { get; set; }
        [JsonProperty("modality")]
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
    public class MetadataTOCPayloadEntry
    {
        [JsonProperty("aaid")]
        public string Aaid { get; set; }
        [JsonProperty("aaguid")]
        public string Aaguid { get; set; }
        [JsonProperty("attestationCertificateKeyIdentifiers")]
        public string[] AttestationCertificateKeyIdentifiers { get; set; }
        [JsonProperty("hash")]
        public string Hash { get; set; }
        [JsonProperty("url")]
        public string Url { get; set; }
        [JsonProperty("biometricStatusReports")]
        public BiometricStatusReport[] BiometricStatusReports { get; set; }
        [JsonProperty("statusReports")]
        public StatusReport[] StatusReports { get; set; }
        [JsonProperty("timeOfLastStatusChange")]
        public string TimeOfLastStatusChange { get; set; }
        [JsonProperty("rogueListURL")]
        public string RogueListURL { get; set; }
        [JsonProperty("rogueListHash")]
        public string RogueListHash { get; set; }
    }
    public class RogueListEntry
    {
        [JsonProperty("sk")]
        public string Sk { get; set; }
        [JsonProperty("date")]
        public string Date { get; set; }
    }
    public class MetadataTOCPayload
    {
        [JsonProperty("legalHeader")]
        public string LegalHeader { get; set; }
        [JsonProperty("no")]
        public int Number { get; set; }
        [JsonProperty("nextUpdate")]
        public string NextUpdate { get; set; }
        [JsonProperty("entries")]
        public MetadataTOCPayloadEntry[] Entries { get; set; }
    }
}
