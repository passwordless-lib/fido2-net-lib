#nullable disable

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Contains an AuthenticatorStatus and additional data associated with it, if any.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#statusreport-dictionary"/>
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
    /// Gets or sets the authenticator version (firmware version) that this status report relates to.
    /// </summary>
    /// <remarks>
    /// For a FIDO_CERTIFIED* status the report applies to this version and higher, until a later status report
    /// supersedes it. For <see cref="AuthenticatorStatus.USER_VERIFICATION_BYPASS"/> it identifies the vulnerable
    /// firmware version; for <see cref="AuthenticatorStatus.UPDATE_AVAILABLE"/>, the updated version now available;
    /// for <see cref="AuthenticatorStatus.SELF_ASSERTION_SUBMITTED"/>, the version the self assertion was based on.
    /// </remarks>
    [JsonPropertyName("authenticatorVersion")]
    public ulong? AuthenticatorVersion { get; set; }

    /// <summary>
    /// Gets or sets the Base64-encoded PKIX certificate identifying the compromised batch attestation certificate
    /// related to the affected authenticators, if applicable.
    /// </summary>
    /// <remarks>
    /// Base64-encoded [RFC4648] (not base64url!) / DER [ITU-X690-2008] PKIX certificate. Typically present for
    /// <see cref="AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE"/>. <see cref="Certificate"/> will typically not
    /// be present when this field is.
    /// </remarks>
    [JsonPropertyName("batchCertificate")]
    public string BatchCertificate { get; set; }

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
    /// Gets or sets the supported certification profiles, as defined in the active version of the Authenticator
    /// Certification Policy document.
    /// </summary>
    /// <remarks>
    /// At the time the specification was written the supported profiles were "consumer" and "enterprise".
    /// </remarks>
    [JsonPropertyName("certificationProfiles")]
    public string[] CertificationProfiles { get; set; }

    /// <summary>
    /// Gets or set the version of the Authenticator Security Requirements the implementation is Certified to.
    /// </summary>
    [JsonPropertyName("certificationRequirementsVersion")]
    public string CertificationRequirementsVersion { get; set; }

    /// <summary>
    /// Gets or sets the ISO-8601 formatted date on which this status will expire, if applicable.
    /// <para>If no date is given, the status is assumed to have no scheduled expiry.</para>
    /// </summary>
    /// <remarks>
    /// For a FIPS140_CERTIFIED_* status this is the sunset date given in the FIPS certificate.
    /// </remarks>
    [JsonPropertyName("sunsetDate")]
    public string SunsetDate { get; set; }

    /// <summary>
    /// Gets or sets the revision number of the FIPS 140 specification, e.g. 3 in the case of FIPS 140-3.
    /// </summary>
    /// <remarks>
    /// Present if and only if <see cref="Status"/> is one of the FIPS140_CERTIFIED_* values.
    /// </remarks>
    [JsonPropertyName("fipsRevision")]
    public ulong? FipsRevision { get; set; }

    /// <summary>
    /// Gets or sets the physical security level of the FIPS certification.
    /// </summary>
    /// <remarks>
    /// Present if and only if <see cref="Status"/> is one of the FIPS140_CERTIFIED_* values. This reflects the
    /// physical security level, which may deviate from the overall level named by the status itself.
    /// </remarks>
    [JsonPropertyName("fipsPhysicalSecurityLevel")]
    public ulong? FipsPhysicalSecurityLevel { get; set; }
}
