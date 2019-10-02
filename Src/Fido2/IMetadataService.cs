using System;
using System.Threading.Tasks;

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
