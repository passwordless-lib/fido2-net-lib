using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fido2NetLib
{
    internal class NullMetadataService : IMetadataService
    {
        bool IMetadataService.ConformanceTesting()
        {
            return false;
        }

        MetadataBLOBPayloadEntry IMetadataService.GetEntry(Guid aaguid)
        {
            return null;
        }

        Task<MetadataBLOBPayloadEntry> IMetadataService.GetEntryAsync(Guid aaguid, CancellationToken cancellationToken)
        {
            return Task.FromResult<MetadataBLOBPayloadEntry>(null);
        }

        Task IMetadataService.InitializeAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        bool IMetadataService.IsInitialized()
        {
            return true;
        }

        Task<bool> IMetadataService.IsInitializedAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(true);
        }
    }
}
