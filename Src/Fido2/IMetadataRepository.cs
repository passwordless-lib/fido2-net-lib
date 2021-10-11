using System.Threading.Tasks;

namespace Fido2NetLib
{
    public interface IMetadataRepository
    {
        Task<MetadataBLOBPayload> GetBLOBAsync();

        Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry);
    }
}
