﻿using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fido2NetLib;

public interface IMetadataService
{
    /// <summary>
    /// Gets the metadata payload entry by a guid asynchronously.
    /// </summary>
    /// <param name="aaguid">The Authenticator Attestation GUID.</param>
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
