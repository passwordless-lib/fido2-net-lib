using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Fido2NetLib
{
    internal class NullMetadataService : IMetadataService
    {
        bool IMetadataService.ConformanceTesting()
        {
            return false;
        }

        MetadataTOCPayloadEntry IMetadataService.GetEntry(Guid aaguid)
        {
            return null;
        }

        Task IMetadataService.Initialize()
        {
            return Task.CompletedTask;
        }

        bool IMetadataService.IsInitialized()
        {
            return true;
        }
    }
}
