using System.Threading;
using System.Threading.Tasks;

namespace Fido2NetLib;

public interface IMetadataRepository
{
    Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default);

    Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default);
}
