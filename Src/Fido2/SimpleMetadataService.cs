using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Fido2NetLib
{
    public class SimpleMetadataService : IMetadataService
    {
        protected readonly List<IMetadataRepository> _repositories;
        protected readonly ConcurrentDictionary<Guid, MetadataStatement> _metadataStatements;
        protected readonly ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry> _entries;
        protected bool _initialized;

        public SimpleMetadataService(IEnumerable<IMetadataRepository> repositories)
        {
            _repositories = repositories.ToList();
            _metadataStatements = new ConcurrentDictionary<Guid, MetadataStatement>();
            _entries = new ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry>();
        }

        public bool ConformanceTesting()
        {
            return _repositories.First().GetType() == typeof(ConformanceMetadataRepository);
        }

        public MetadataBLOBPayloadEntry? GetEntry(Guid aaguid)
        {
            if (!IsInitialized())
                throw new InvalidOperationException("MetadataService must be initialized");

            if (_entries.TryGetValue(aaguid, out MetadataBLOBPayloadEntry? entry))
            {
                if (_metadataStatements.ContainsKey(aaguid))
                {
                    entry.MetadataStatement = _metadataStatements[aaguid];
                }

                return entry;
            }
            else
            {
                return null;
            }
        }

        protected virtual async Task LoadEntryStatementAsync(IMetadataRepository repository, MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry)
        {
            if (entry.AaGuid != null)
            {
                var statement = await repository.GetMetadataStatementAsync(blob, entry);

                if (!string.IsNullOrWhiteSpace(statement?.AaGuid))
                {
                    _metadataStatements.TryAdd(Guid.Parse(statement.AaGuid), statement);
                }
            }
        }

        protected virtual async Task InitializeRepositoryAsync(IMetadataRepository repository)
        {
            var blob = await repository.GetBLOBAsync();

            foreach (var entry in blob.Entries)
            {
                if (!string.IsNullOrEmpty(entry.AaGuid))
                {
                    if (_entries.TryAdd(Guid.Parse(entry.AaGuid), entry))
                    {
                        //Load if it doesn't already exist
                        await LoadEntryStatementAsync(repository, blob, entry);
                    }
                }
            }
        }

        public virtual async Task InitializeAsync()
        {
            foreach (var repository in _repositories)
            {
                await InitializeRepositoryAsync(repository);
            }
            _initialized = true;
        }

        public virtual bool IsInitialized()
        {
            return _initialized;
        }
    }
}
