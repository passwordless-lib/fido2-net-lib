using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;

namespace Fido2NetLib
{
    public interface IMetadataService
    {
        MetadataTOCPayloadEntry GetEntry(Guid aaguid);
        bool ConformanceTesting();
        bool IsInitialized();
        Task Initialize();
    }
}
