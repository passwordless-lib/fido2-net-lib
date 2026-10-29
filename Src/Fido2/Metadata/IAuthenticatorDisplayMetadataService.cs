using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fido2NetLib;

/// <summary>
/// Resolves an AAGUID to a display-only name and icon(s), from an unsigned source such as
/// <see cref="ConvenienceMetadataService"/> or <see cref="FileSystemDisplayMetadataRepository"/>.
/// </summary>
/// <remarks>
/// Deliberately unrelated to <see cref="IMetadataService"/>/<see cref="IMetadataRepository"/>: an
/// implementation of this interface carries no trust information and must never be consulted by
/// <see cref="TrustAnchor"/> or any attestation/assertion verification path.
/// </remarks>
public interface IAuthenticatorDisplayMetadataService
{
    /// <summary>
    /// Looks up the display name and icon(s) for an authenticator model.
    /// </summary>
    /// <param name="aaguid">The authenticator model's AAGUID.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The display info, or <see langword="null"/> if this AAGUID is not known to the source.</returns>
    Task<AuthenticatorDisplayInfo?> GetDisplayInfoAsync(Guid aaguid, CancellationToken cancellationToken = default);
}
