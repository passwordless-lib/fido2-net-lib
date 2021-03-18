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

        protected readonly IDictionary<Guid, MetadataTOCPayloadEntry> _entries;
        protected MetadataTOCPayload _toc;

        public FileSystemMetadataRepository(string path)
        {
            _path = path;
            _entries = new Dictionary<Guid, MetadataTOCPayloadEntry>();
        }

        public async Task<MetadataStatement> GetMetadataStatement(MetadataTOCPayload toc, MetadataTOCPayloadEntry entry)
        {
            if (_toc == null)
                await GetToc();

            if (!string.IsNullOrEmpty(entry.AaGuid) && Guid.TryParse(entry.AaGuid, out Guid parsedAaGuid))
            {
                if (_entries.ContainsKey(parsedAaGuid))
                    return _entries[parsedAaGuid].MetadataStatement;
            }

            return null;
        }

        public Task<MetadataTOCPayload> GetToc()
        {
            if (Directory.Exists(_path))
            {
                foreach (var filename in Directory.GetFiles(_path))
                {
                    var rawStatement = File.ReadAllText(filename);
                    var statement = JsonConvert.DeserializeObject<MetadataStatement>(rawStatement);
                    var conformanceEntry = new MetadataTOCPayloadEntry
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

            _toc = new MetadataTOCPayload()
            {
                Entries = _entries.Select(o => o.Value).ToArray(),
                NextUpdate = "", //Empty means it won't get cached
                LegalHeader = "Local FAKE",
                Number = 1
            };

            return Task.FromResult(_toc);
        }
    }
}
