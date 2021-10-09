using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Fido2NetLib
{
    /// <summary>
    /// Contains the current BiometricStatusReport of one of the authenticator's biometric component.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-service-v2.0-rd-20180702.html#biometricstatusreport-dictionary"/>
    /// </remarks>
    public class BiometricStatusReport
    {
        /// <summary>
        /// Gets or sets the level of the biometric certification of this biometric component of the authenticator.
        /// </summary>
        [JsonPropertyName("certLevel"), Required]
        public ushort CertLevel { get; set; }
        /// <summary>
        /// Gets or sets a single USER_VERIFY constant indicating the modality of the biometric component.
        /// </summary>
        /// <remarks>
        /// This is not a bit flag combination. 
        /// This value MUST be non-zero and this value MUST correspond to one or more entries in field userVerificationDetails in the related Metadata Statement.
        /// </remarks>
        [JsonPropertyName("modality"), Required]
        public ulong Modality { get; set; }

        /// <summary>
        /// Gets or sets a ISO-8601 formatted date since when the certLevel achieved, if applicable. 
        /// <para>If no date is given, the status is assumed to be effective while present.</para>
        /// </summary>
        [JsonPropertyName("effectiveDate")]
        public string EffectiveDate { get; set; }

        /// <summary>
        /// Gets or sets the externally visible aspects of the Biometric Certification evaluation.
        /// </summary>
        [JsonPropertyName("certificationDescriptor")]
        public string CertificationDescriptor { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier for the issued Biometric Certification.
        /// </summary>
        [JsonPropertyName("certificateNumber")]
        public string CertificateNumber { get; set; }

        /// <summary>
        /// Gets or sets the  version of the Biometric Certification Policy the implementation is Certified to.
        /// </summary>
        /// <remarks>
        /// For example: "1.0.0".
        /// </remarks>
        [JsonPropertyName("certificationPolicyVersion")]
        public string CertificationPolicyVersion { get; set; }

        /// <summary>
        /// Gets or sets the version of the Biometric Requirements the implementation is certified to.
        /// </summary>
        /// <remarks>
        /// For example: "1.0.0".
        /// </remarks>
        [JsonPropertyName("certificationRequirementsVersion")]
        public string CertificationRequirementsVersion { get; set; }
    }
}
