using System.Collections.Concurrent;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Fido2NetLib;

public class ConformanceMetadataService : IMetadataService
{
    protected readonly List<IMetadataRepository> _repositories;
    protected readonly ConcurrentDictionary<Guid, MetadataStatement> _metadataStatements;
    protected readonly ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry> _entries;
    protected bool _initialized;
    private readonly ILogger _logger;

    /// <param name="repositories">The metadata sources to load.</param>
    /// <param name="logger">Where loading is reported.</param>
    public ConformanceMetadataService(IEnumerable<IMetadataRepository> repositories, ILogger<ConformanceMetadataService>? logger = null)
    {
        _repositories = repositories.ToList();
        _metadataStatements = new ConcurrentDictionary<Guid, MetadataStatement>();
        _entries = new ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry>();
        _logger = logger ?? NullLogger<ConformanceMetadataService>.Instance;
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
        if (entry.AaGuid.HasValue)
        {
            var statement = await repository.GetMetadataStatementAsync(blob, entry, cancellationToken);

            if (statement?.AaGuid is Guid aaGuid)
            {
                _metadataStatements.TryAdd(aaGuid, statement);
            }
        }
    }

    protected virtual async Task InitializeRepositoryAsync(IMetadataRepository repository, CancellationToken cancellationToken)
    {
        var blob = await repository.GetBLOBAsync(cancellationToken);
        int loaded = 0;

        foreach (var entry in blob.Entries)
        {
            if (entry.AaGuid is Guid aaGuid)
            {
                if (_entries.TryAdd(aaGuid, entry))
                {
                    // Load if it doesn't already exist
                    await LoadEntryStatementAsync(repository, blob, entry, cancellationToken);
                    loaded++;
                }
            }
        }

        _logger.LogInformation("Loaded {EntryCount} of {TotalEntries} metadata entries from {Repository}; the rest were already known or have no AAGUID",
            loaded, blob.Entries.Length, repository.GetType().Name);
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

    public virtual Task<MetadataBLOBPayloadEntry?> GetEntryAsync(Guid aaGuid, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(GetEntry(aaGuid));
    }
}
