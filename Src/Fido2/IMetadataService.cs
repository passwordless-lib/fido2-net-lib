using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Fido2NetLib;

public interface IMetadataService
{
    /// <summary>
    /// Gets the metadata payload entry by a guid asynchronously.
    /// </summary>
    /// <param name="aaguid">The Authenticator Attestation GUID.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>Returns the entry; Otherwise <c>null</c>.</returns>
    Task<MetadataBLOBPayloadEntry?> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a value indicating whether the internal access token is valid.
    /// </summary>
    /// <returns>
    /// Returns <c>true</c> if access token is valid, or <c>false</c> if the access token is equal to an invalid token value.
    /// </returns>
    bool ConformanceTesting();
}

/// <summary>
/// Optional companion to <see cref="IMetadataService"/> for implementations that can also resolve a metadata
/// entry identified only by <see cref="MetadataBLOBPayloadEntry.AttestationCertificateKeyIdentifiers"/> -- i.e.
/// authenticators without an AAID or AAGUID in MDS, such as FIDO U2F authenticators. This is a separate,
/// optional interface (rather than a member of <see cref="IMetadataService"/>) so that existing
/// <see cref="IMetadataService"/> implementations and test doubles are unaffected.
/// </summary>
public interface IMetadataServiceAttestationCertificateLookup
{
    /// <summary>
    /// Gets the metadata payload entry by AAGUID, falling back to matching <paramref name="attestationCertificates"/>
    /// against <see cref="MetadataBLOBPayloadEntry.AttestationCertificateKeyIdentifiers"/> when the AAGUID lookup
    /// finds nothing.
    /// </summary>
    /// <param name="aaguid">The Authenticator Attestation GUID.</param>
    /// <param name="attestationCertificates">The attestation trust path certificates from the registration ceremony, if any.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>Returns the entry; Otherwise <c>null</c>.</returns>
    Task<MetadataBLOBPayloadEntry?> GetEntryAsync(Guid aaguid, X509Certificate2[]? attestationCertificates, CancellationToken cancellationToken = default);
}
