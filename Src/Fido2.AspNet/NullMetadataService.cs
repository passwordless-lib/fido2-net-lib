using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fido2NetLib;

internal sealed class NullMetadataService : IMetadataService
{
    public Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default)
    {
        return Task.FromResult((MetadataBLOBPayloadEntry)null);
    }

    public bool ConformanceTesting()
    {
        return false;
    }
}
