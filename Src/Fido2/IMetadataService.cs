using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fido2NetLib
{
    /// <summary>
    /// The FIDO2 metadata service.
    /// </summary>
    public interface IMetadataService
    {
        /// <summary>
        /// Gets the metadata payload entry by a guid.
        /// </summary>
        /// <param name="aaguid">The Authenticator Attestation GUID.</param>
        /// <returns>Returns the entry; Otherwise <c>null</c>.</returns>
        [Obsolete("Please use GetEntryAsync(aaguid) instead.")]
        MetadataBLOBPayloadEntry? GetEntry(Guid aaguid);

        /// <summary>
        /// Gets the metadata payload entry by a guid.
        /// </summary>
        /// <param name="aaguid">The Authenticator Attestation GUID.</param>
        /// <param name="cancellationToken">Cancellation token for this operation.</param>
        /// <returns>Returns the entry; Otherwise <c>null</c>.</returns>
        Task<MetadataBLOBPayloadEntry?> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return Task.FromResult(this?.GetEntry(aaguid));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>
        /// Gets a value indicating whether the internal access token is valid.
        /// </summary>
        /// <returns>
        /// Returns <c>true</c> if access token is valid, or <c>false</c> if the access token is equal to an invalid token value.
        /// </returns>
        bool ConformanceTesting();

        /// <summary>
        /// Gets a value indicating whether the metadata service is initialized.
        /// </summary>
        /// <returns>
        /// Returns <c>true</c> if the metadata service is initialized, or <c>false</c> if the metadata service is not initialized.
        /// </returns>
        [Obsolete("Please use IsInitializedAsync() instead.")]
        bool IsInitialized();

        /// <summary>
        /// Gets a value indicating whether the metadata service is initialized.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for this operation.</param>
        /// <returns>
        /// Returns <c>true</c> if the metadata service is initialized, or <c>false</c> if the metadata service is not initialized.
        /// </returns>
        Task<bool> IsInitializedAsync(CancellationToken cancellationToken = default)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return Task.FromResult(IsInitialized());
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>
        /// Initializes the metadata service.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for this operation.</param>
        Task InitializeAsync(CancellationToken cancellationToken = default);
    }
}
