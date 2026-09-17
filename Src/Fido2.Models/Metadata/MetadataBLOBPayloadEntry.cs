#nullable disable

using System;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Represents the metadata BLOB payload data strucutre.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary"/>
/// </remarks>
public sealed class MetadataBLOBPayloadEntry
{
    /// <summary>
    /// Gets or sets the AAID.
    /// <para>The AAID of the authenticator this metadata BLOB payload entry relates to.</para>
    /// </summary>
    [JsonPropertyName("aaid")]
    public string Aaid { get; set; }

    /// <summary>
    /// Gets or sets the AAGUID.
    /// <para>The Authenticator Attestation GUID.</para>
    /// </summary>
    [JsonPropertyName("aaguid")]
    public Guid? AaGuid { get; set; }

    /// <summary>
    /// Gets or sets a list of the attestation certificate public key identifiers encoded as hex string.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    ///     <item>The hex string must not contain any non-hex characters (e.g. spaces).</item>
    ///     <item>All hex letters must be lower case.</item>
    ///     <item>This field must be set if neither aaid nor aaguid are set.</item>
    ///     <item>Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.</item>
    /// </list>
    /// <para>FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.</para>
    /// </remarks>
    [JsonPropertyName("attestationCertificateKeyIdentifiers")]
    public string[] AttestationCertificateKeyIdentifiers { get; set; }

    /// <summary>
    /// Gets or sets the metadata statement.
    /// </summary>
    [JsonPropertyName("metadataStatement")]
    public MetadataStatement MetadataStatement { get; set; }

    /// <summary>
    /// Gets or sets the status of the FIDO Biometric Certification of one or more biometric components of the Authenticator.
    /// </summary>
    [JsonPropertyName("biometricStatusReports")]
    public BiometricStatusReport[] BiometricStatusReports { get; set; }

    /// <summary>
    /// Gets or sets an array of status reports applicable to this authenticator.
    /// </summary>
    [JsonPropertyName("statusReports"), Required]
    public StatusReport[] StatusReports { get; set; }

    /// <summary>
    /// Gets or sets ISO-8601 formatted date since when the status report array was set to the current value.
    /// </summary>
    [JsonPropertyName("timeOfLastStatusChange")]
    public string TimeOfLastStatusChange { get; set; }

    /// <summary>
    /// Gets or sets an URL of a list of rogue (i.e. untrusted) individual authenticators.
    /// </summary>
    [JsonPropertyName("rogueListURL")]
    public string RogueListURL { get; set; }

    /// <summary>
    /// Gets or sets the hash value computed of <see cref="RogueListURL"/>.
    /// </summary>
    /// <remarks>
    /// This hash value must be present and non-empty whenever rogueListURL is present.
    /// </remarks>
    [JsonPropertyName("rogueListHash")]
    public string RogueListHash { get; set; }

    /// <summary>
    /// Gets the latest, most current status report for the authenticator: the one with the most recent
    /// <see cref="StatusReport.EffectiveDate"/>.
    /// </summary>
    /// <remarks>
    /// The Metadata Service does not define an order for <see cref="StatusReports"/>, and the published BLOB
    /// lists most entries newest first, so the array position says nothing about currency. A report whose
    /// effective date is missing or unparseable sorts before every dated one; among reports with the same
    /// effective date (or none), the last in the array wins, as the spec's oldest-first examples suggest.
    /// </remarks>
    /// <returns>Latest status report, or null if there are no reports.</returns>
    public StatusReport GetLatestStatusReport()
    {
        if (StatusReports is not { Length: > 0 })
            return null;

        StatusReport latest = null;
        DateTimeOffset latestEffectiveDate = DateTimeOffset.MinValue;

        foreach (var report in StatusReports)
        {
            var effectiveDate = ParseEffectiveDate(report.EffectiveDate);

            if (latest is null || effectiveDate >= latestEffectiveDate)
            {
                latest = report;
                latestEffectiveDate = effectiveDate;
            }
        }

        return latest;
    }

    /// <summary>
    /// Parses an ISO 8601 effective date ("2023-12-20", or a full date-time); anything else counts as the
    /// oldest possible date.
    /// </summary>
    private static DateTimeOffset ParseEffectiveDate(string effectiveDate)
    {
        return DateTimeOffset.TryParse(effectiveDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : DateTimeOffset.MinValue;
    }

    /// <summary>
    /// Computes the certificate's public key identifier per RFC 5280 §4.2.1.2 method (1): the SHA-1 hash of the
    /// value of the BIT STRING subjectPublicKey (excluding the tag, length, and number of unused bits), encoded
    /// as a lower-case hex string. This is the identifier format used by <see cref="AttestationCertificateKeyIdentifiers"/>.
    /// </summary>
    public static string ComputeAttestationCertificateKeyIdentifier(X509Certificate2 attestationCertificate)
    {
        ArgumentNullException.ThrowIfNull(attestationCertificate);

        return Convert.ToHexString(SHA1.HashData(attestationCertificate.PublicKey.EncodedKeyValue.RawData)).ToLowerInvariant();
    }

    /// <summary>
    /// Determines whether this entry is identified by (i.e. its <see cref="AttestationCertificateKeyIdentifiers"/>
    /// contains the key identifier of) one of the given attestation certificates. Per the FIDO Metadata Service
    /// spec, this is how authenticators without an AAID or AAGUID (e.g. FIDO U2F authenticators) are identified.
    /// </summary>
    public bool MatchesAttestationCertificate(X509Certificate2 attestationCertificate)
    {
        if (AttestationCertificateKeyIdentifiers is not { Length: > 0 })
            return false;

        var keyIdentifier = ComputeAttestationCertificateKeyIdentifier(attestationCertificate);

        return AttestationCertificateKeyIdentifiers.Contains(keyIdentifier, StringComparer.OrdinalIgnoreCase);
    }
}
