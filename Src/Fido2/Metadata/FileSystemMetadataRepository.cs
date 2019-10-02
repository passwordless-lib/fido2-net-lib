using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;
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

        public async Task<MetadataStatement> GetMetadataStatement(MetadataTOCPayloadEntry entry)
        {
            if (_toc == null) await GetToc();

            Guid parsedAaGuid;
            if(!string.IsNullOrEmpty(entry.AaGuid) && Guid.TryParse(entry.AaGuid, out parsedAaGuid))
            {
                if (_entries.ContainsKey(parsedAaGuid)) return _entries[parsedAaGuid].MetadataStatement;
            }

            return null;
        }

        public Task<MetadataTOCPayload> GetToc()
        {
            if (System.IO.Directory.Exists(_path))
            {
                foreach (var filename in System.IO.Directory.GetFiles(_path))
                {
                    var rawStatement = System.IO.File.ReadAllText(filename);
                    var statement = JsonConvert.DeserializeObject<MetadataStatement>(rawStatement);
                    var conformanceEntry = new MetadataTOCPayloadEntry
                    {
                        AaGuid = statement.AaGuid,
                        MetadataStatement = statement,
                        StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } }
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
