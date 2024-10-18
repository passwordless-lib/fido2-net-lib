using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Contains an AuthenticatorStatus and additional data associated with it, if any.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary"/>
/// </remarks>
public sealed class StatusReport
{
    /// <summary>
    /// Gets or sets the status of the authenticator.
    /// <para>Additional fields may be set depending on this value.</para>
    /// </summary>
    [JsonPropertyName("status"), Required]
    public AuthenticatorStatus Status { get; set; }

    /// <summary>
    /// Gets or set the ISO-8601 formatted date since when the status code was set, if applicable.
    /// <para>If no date is given, the status is assumed to be effective while present.</para>
    /// </summary>
    [JsonPropertyName("effectiveDate")]
    public string EffectiveDate { get; set; }

    /// <summary>
    /// Gets or sets Base64-encoded PKIX certificate value related to the current status, if applicable.
    /// </summary>
    /// <remarks>
    /// Base64-encoded [RFC4648] (not base64url!) / DER [ITU-X690-2008] PKIX certificate.
    /// </remarks>
    [JsonPropertyName("certificate")]
    public string Certificate { get; set; }

    /// <summary>
    /// Gets or sets the HTTPS URL where additional information may be found related to the current status, if applicable.
    /// </summary>
    /// <remarks>
    /// For example a link to a web page describing an available firmware update in the case of status <see cref="AuthenticatorStatus.UPDATE_AVAILABLE"/>, or a link to a description of an identified issue in the case of status <see cref="AuthenticatorStatus.USER_VERIFICATION_BYPASS"/>.
    /// </remarks>
    [JsonPropertyName("url")]
    public string Url { get; set; }

    /// <summary>
    /// Gets or sets a description of the externally visible aspects of the Authenticator Certification evaluation.
    /// </summary>
    [JsonPropertyName("certificationDescriptor")]
    public string CertificationDescriptor { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier for the issued Certification.
    /// </summary>
    [JsonPropertyName("certificateNumber")]
    public string CertificateNumber { get; set; }

    /// <summary>
    /// Gets or set the version of the Authenticator Certification Policy the implementation is Certified to.
    /// </summary>
    [JsonPropertyName("certificationPolicyVersion")]
    public string CertificationPolicyVersion { get; set; }

    /// <summary>
    /// Gets or set the version of the Authenticator Security Requirements the implementation is Certified to.
    /// </summary>
    [JsonPropertyName("certificationRequirementsVersion")]
    public string CertificationRequirementsVersion { get; set; }
}
