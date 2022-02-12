using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Fido2NetLib
{
    public class ConformanceMetadataService : IMetadataService
    {
        protected readonly List<IMetadataRepository> _repositories;
        protected readonly ConcurrentDictionary<Guid, MetadataStatement> _metadataStatements;
        protected readonly ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry> _entries;
        protected bool _initialized;

        public ConformanceMetadataService(IEnumerable<IMetadataRepository> repositories)
        {
            _repositories = repositories.ToList();
            _metadataStatements = new ConcurrentDictionary<Guid, MetadataStatement>();
            _entries = new ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry>();
        }

        public bool ConformanceTesting()
        {
            return _repositories[0] is ConformanceMetadataRepository;
        }

        protected virtual MetadataBLOBPayloadEntry? GetEntry(Guid aaguid)
        {
            if (!IsInitialized())
                throw new InvalidOperationException("MetadataService must be initialized");

            if (_entries.TryGetValue(aaguid, out MetadataBLOBPayloadEntry? entry))
            {
                if (_metadataStatements.TryGetValue(aaguid, out var metadataStatement))
                {
                    entry.MetadataStatement = metadataStatement;
                }

                return entry;
            }
            else
            {
                return null;
            }
        }

        protected virtual async Task LoadEntryStatementAsync(IMetadataRepository repository, MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken)
        {
            if (entry.AaGuid != null)
            {
                var statement = await repository.GetMetadataStatementAsync(blob, entry, cancellationToken);

                if (!string.IsNullOrWhiteSpace(statement?.AaGuid))
                {
                    _metadataStatements.TryAdd(Guid.Parse(statement.AaGuid), statement);
                }
            }
        }

        protected virtual async Task InitializeRepositoryAsync(IMetadataRepository repository, CancellationToken cancellationToken)
        {
            var blob = await repository.GetBLOBAsync(cancellationToken);

            foreach (var entry in blob.Entries)
            {
                if (!string.IsNullOrEmpty(entry.AaGuid))
                {
                    if (_entries.TryAdd(Guid.Parse(entry.AaGuid), entry))
                    {
                        //Load if it doesn't already exist
                        await LoadEntryStatementAsync(repository, blob, entry, cancellationToken);
                    }
                }
            }
        }

        public virtual async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            foreach (var repository in _repositories)
            {
                await InitializeRepositoryAsync(repository, cancellationToken);
            }
            _initialized = true;
        }

        public virtual bool IsInitialized()
        {
            return _initialized;
        }

        public virtual Task<MetadataBLOBPayloadEntry?> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(GetEntry(aaguid));
        }
    }
}
