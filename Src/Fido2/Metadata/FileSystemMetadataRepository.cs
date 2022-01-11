using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Fido2NetLib
{
    public sealed class FileSystemMetadataRepository : IMetadataRepository
    {
        private readonly string _path;
        private readonly IDictionary<Guid, MetadataBLOBPayloadEntry> _entries;
        private MetadataBLOBPayload? _blob;

        public FileSystemMetadataRepository(string path)
        {
            _path = path;
            _entries = new Dictionary<Guid, MetadataBLOBPayloadEntry>();
        }

        public async Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
        {
            if (_blob is null)
                await GetBLOBAsync(cancellationToken);

            if (!string.IsNullOrEmpty(entry.AaGuid) && Guid.TryParse(entry.AaGuid, out Guid parsedAaGuid))
            {
                if (_entries.ContainsKey(parsedAaGuid))
                    return _entries[parsedAaGuid].MetadataStatement;
            }

            return null;
        }

        public async Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            if (Directory.Exists(_path))
            {
                foreach (var filename in Directory.GetFiles(_path))
                {
                    await using var fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read);
                    var statement = await JsonSerializer.DeserializeAsync<MetadataStatement>(fileStream, cancellationToken:cancellationToken);
                    _ = statement ?? throw new NullReferenceException(nameof(statement));
                    var conformanceEntry = new MetadataBLOBPayloadEntry
                    {
                        AaGuid = statement.AaGuid,
                        MetadataStatement = statement,
                        StatusReports = new StatusReport[] 
                        { 
                            new StatusReport 
                            { 
                                Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED 
                            } 
                        }
                    };
                    if (null != conformanceEntry.AaGuid) _entries.Add(new Guid(conformanceEntry.AaGuid), conformanceEntry);
                }
            }

            _blob = new MetadataBLOBPayload()
            {
                Entries = _entries.Select(o => o.Value).ToArray(),
                NextUpdate = "", //Empty means it won't get cached
                LegalHeader = "Local FAKE",
                Number = 1
            };

            return _blob;
        }
    }
}
