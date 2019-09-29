using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;


namespace Fido2NetLib
{
    public interface IMetadataRepository
    {
        Task<MetadataTOCPayload> GetToc();

        Task<MetadataStatement> GetMetadataStatement(MetadataTOCPayloadEntry entry);
    }
}
