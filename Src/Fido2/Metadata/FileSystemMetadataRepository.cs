using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Serialization;

namespace Fido2NetLib;

public sealed class FileSystemMetadataRepository : IMetadataRepository
{
    private readonly string _directoryPath;
    private readonly Dictionary<Guid, MetadataBLOBPayloadEntry> _entries;
    private MetadataBLOBPayload? _blob;

    public FileSystemMetadataRepository(string directoryPath)
    {
        _directoryPath = directoryPath;
        _entries = new Dictionary<Guid, MetadataBLOBPayloadEntry>();
    }

    public async Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
    {
        if (_blob is null)
            await GetBLOBAsync(cancellationToken);

        if (entry.AaGuid is Guid aaGuid && _entries.TryGetValue(aaGuid, out var found))
        {
            return found.MetadataStatement;
        }

        return null;
    }

    public async Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
    {
        if (Directory.Exists(_directoryPath))
        {
            foreach (var filename in Directory.GetFiles(_directoryPath))
            {
                await using var fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read);
                MetadataStatement statement = await JsonSerializer.DeserializeAsync(fileStream, FidoModelSerializerContext.Default.MetadataStatement, cancellationToken: cancellationToken) ?? throw new NullReferenceException(nameof(statement));
                var conformanceEntry = new MetadataBLOBPayloadEntry
                {
                    AaGuid = statement.AaGuid,
                    MetadataStatement = statement,
                    StatusReports =
                    [
                        new StatusReport
                        {
                            Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                        }
                    ]
                };
                if (null != conformanceEntry.AaGuid)
                    _entries.Add(conformanceEntry.AaGuid.Value, conformanceEntry);
            }
        }

        _blob = new MetadataBLOBPayload()
        {
            Entries = _entries.Select(static o => o.Value).ToArray(),
            NextUpdate = "", //Empty means it won't get cached
            LegalHeader = "Local FAKE",
            Number = 1
        };

        return _blob;
    }
}
