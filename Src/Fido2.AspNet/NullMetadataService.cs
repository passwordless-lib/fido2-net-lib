using System;
using System.Threading.Tasks;

namespace Fido2NetLib
{
    internal class NullMetadataService : IMetadataService
    {
        public Task<MetadataBLOBPayloadEntry?> GetEntryAsync(Guid aaguid)
        {
            return Task.FromResult((MetadataBLOBPayloadEntry)null);
        }

        public bool ConformanceTesting()
        {
            return false;
        }
    }
}
