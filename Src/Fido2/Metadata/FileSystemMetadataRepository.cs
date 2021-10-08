using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class FileSystemMetadataRepository : IMetadataRepository
    {
        protected readonly string _path;

        protected readonly IDictionary<Guid, MetadataBLOBPayloadEntry> _entries;
        protected MetadataBLOBPayload? _blob;

        public FileSystemMetadataRepository(string path)
        {
            _path = path;
            _entries = new Dictionary<Guid, MetadataBLOBPayloadEntry>();
        }

        public async Task<MetadataStatement?> GetMetadataStatement(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry)
        {
            if (_blob is null)
                await GetBLOB();

            if (!string.IsNullOrEmpty(entry.AaGuid) && Guid.TryParse(entry.AaGuid, out Guid parsedAaGuid))
            {
                if (_entries.ContainsKey(parsedAaGuid))
                    return _entries[parsedAaGuid].MetadataStatement;
            }

            return null;
        }

        public Task<MetadataBLOBPayload> GetBLOB()
        {
            if (Directory.Exists(_path))
            {
                foreach (var filename in Directory.GetFiles(_path))
                {
                    var rawStatement = File.ReadAllText(filename);
                    var statement = JsonConvert.DeserializeObject<MetadataStatement>(rawStatement);
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

            return Task.FromResult(_blob);
        }
    }
}
