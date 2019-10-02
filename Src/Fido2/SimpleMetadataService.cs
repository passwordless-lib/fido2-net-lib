using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class SimpleMetadataService : IMetadataService
    {

        protected readonly List<IMetadataRepository> _repositories;
        protected readonly ConcurrentDictionary<Guid, MetadataStatement> _metadataStatements;
        protected readonly ConcurrentDictionary<Guid, MetadataTOCPayloadEntry> _entries;
        protected bool _initialized;


        public SimpleMetadataService(IEnumerable<IMetadataRepository> repositories)
        {
            _repositories = repositories.ToList();
            _metadataStatements = new ConcurrentDictionary<Guid, MetadataStatement>();
            _entries = new ConcurrentDictionary<Guid, MetadataTOCPayloadEntry>();
        }

        public bool ConformanceTesting()
        {
            if (_repositories.First().GetType() == typeof(ConformanceMetadataRepository)) return true;
            return false;
        }

        public MetadataTOCPayloadEntry GetEntry(Guid aaguid)
        {
            if (!IsInitialized()) throw new InvalidOperationException("MetadataService must be initialized");

            if (_entries.ContainsKey(aaguid))
            {
                var entry = _entries[aaguid];

                if (_metadataStatements.ContainsKey(aaguid))
                {
                    if (entry.Hash != _metadataStatements[aaguid].Hash) throw new Fido2VerificationException("Authenticator metadata statement has invalid hash");
                    entry.MetadataStatement = _metadataStatements[aaguid];
                }

                return entry;
            }

            else return null;
        }

        protected virtual async Task LoadEntryStatement(IMetadataRepository repository, MetadataTOCPayloadEntry entry)
        {
            if (entry.AaGuid != null)
            {
                var statement = await repository.GetMetadataStatement(entry);

                if (!string.IsNullOrWhiteSpace(statement.AaGuid))
                {
                    _metadataStatements.TryAdd(Guid.Parse(statement.AaGuid), statement);

                    var statementJson = JsonConvert.SerializeObject(statement, Formatting.Indented);
                }
            }
        }

        protected virtual async Task InitializeClient(IMetadataRepository repository)
        {
            var toc = await repository.GetToc();

            foreach (var entry in toc.Entries)
            {
                if (!string.IsNullOrEmpty(entry.AaGuid))
                {
                    if (_entries.TryAdd(Guid.Parse(entry.AaGuid), entry))
                    {
                        //Load if it doesn't already exist
                        await LoadEntryStatement(repository, entry);
                    }
                }
            }
        }

        public virtual async Task Initialize()
        {
            foreach (var client in _repositories)
            {
                await InitializeClient(client);
            }
            _initialized = true;
        }

        public virtual bool IsInitialized()
        {
            return _initialized;
        }
    }
}
