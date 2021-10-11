using System;
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
        MetadataBLOBPayloadEntry? GetEntry(Guid aaguid);

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
        bool IsInitialized();

        /// <summary>
        /// Initializes the metadata service.
        /// </summary>
        Task InitializeAsync();
    }
}
