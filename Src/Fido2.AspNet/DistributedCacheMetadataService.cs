using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace Fido2NetLib
{
    public class DistributedCacheMetadataService : IMetadataService
    {
        protected readonly IDistributedCache _cache;
        protected readonly List<IMetadataRepository> _repositories;
        protected readonly ILogger<DistributedCacheMetadataService> _log;
        protected bool _initialized;
        protected readonly TimeSpan _defaultCacheInterval = TimeSpan.FromHours(25);

        protected readonly ConcurrentDictionary<Guid, MetadataStatement> _metadataStatements;
        protected readonly ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry> _entries;

        protected const string CACHE_PREFIX = "DistributedCacheMetadataService";

        public DistributedCacheMetadataService(
            IEnumerable<IMetadataRepository> repositories,
            IDistributedCache cache,
            ILogger<DistributedCacheMetadataService> log)
        {
            _repositories = repositories.ToList();
            _cache = cache;
            _metadataStatements = new ConcurrentDictionary<Guid, MetadataStatement>();
            _entries = new ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry>();
            _log = log;
        }

        public virtual bool ConformanceTesting()
        {
            return _repositories.First().GetType() == typeof(ConformanceMetadataRepository);
        }

        public virtual MetadataBLOBPayloadEntry GetEntry(Guid aaguid)
        {
            if (!IsInitialized())
                throw new InvalidOperationException("MetadataService must be initialized");

            if (_entries.TryGetValue(aaguid, out MetadataBLOBPayloadEntry entry))
            {
                if (_metadataStatements.TryGetValue(aaguid, out var statement))
                {
                    entry.MetadataStatement = statement;
                }

                return entry;
            }
            else
            {
                return null;
            }
        }

        protected virtual string GetTocCacheKey(IMetadataRepository repository)
        {
            return $"{CACHE_PREFIX}:{repository.GetType().Name}:TOC";
        }

        protected virtual string GetEntryCacheKey(IMetadataRepository repository, Guid aaGuid)
        {
            return $"{CACHE_PREFIX}:{repository.GetType().Name}:Entry:{aaGuid}";
        }

        protected virtual async Task LoadTocEntryStatement(
            IMetadataRepository repository,
            MetadataBLOBPayload blob,
            MetadataBLOBPayloadEntry entry,
            DateTime? cacheUntil = null)
        {
            if (entry.AaGuid != null && !_entries.ContainsKey(Guid.Parse(entry.AaGuid)))
            {
                var entryAaGuid = Guid.Parse(entry.AaGuid);

                var cacheKey = GetEntryCacheKey(repository, entryAaGuid);

                var cachedEntry = await _cache.GetStringAsync(cacheKey);
                if (cachedEntry != null)
                {
                    var statement = JsonSerializer.Deserialize<MetadataStatement>(cachedEntry);
                    if (!string.IsNullOrWhiteSpace(statement.AaGuid))
                    {
                        var aaGuid = Guid.Parse(statement.AaGuid);
                        _metadataStatements.TryAdd(aaGuid, statement);
                        _entries.TryAdd(aaGuid, entry);
                    }
                }
                else
                {
                    _log?.LogInformation("Entry for {0} {1} not cached so loading from MDS...", entry.AaGuid, entry.MetadataStatement?.Description ?? entry.StatusReports?.FirstOrDefault().CertificationDescriptor ?? "(unknown)");

                    try
                    {
                        if (!string.IsNullOrWhiteSpace(entry.AaGuid))
                        {
                            var statementJson = JsonSerializer.Serialize(entry.MetadataStatement, new JsonSerializerOptions { WriteIndented = true });

                            _log?.LogDebug("{0}:{1}\n{2}", entry.AaGuid, entry.MetadataStatement.Description, statementJson);

                            var aaGuid = Guid.Parse(entry.AaGuid);

                            _metadataStatements.TryAdd(aaGuid, entry.MetadataStatement);
                            _entries.TryAdd(aaGuid, entry);

                            if (cacheUntil.HasValue)
                            {
                                await _cache.SetStringAsync(cacheKey, statementJson, new DistributedCacheEntryOptions
                                {
                                    AbsoluteExpiration = cacheUntil
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _log?.LogError(ex, "Error getting MetadataStatement from {0} for AAGUID '{1}' ", repository.GetType().Name, entry.AaGuid);
                        throw;
                    }
                }
            }
        }

        private DateTime? GetCacheUntilTime(MetadataBLOBPayload blob)
        {
            if (!string.IsNullOrWhiteSpace(blob?.NextUpdate)
                && DateTime.TryParseExact(
                    blob.NextUpdate,
                    new[] { "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss", "o" }, //Sould be ISO8601 date but allow for other ISO formats too
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                    out var parsedDate))
            {
                //NextUpdate is in the past to default to a useful number that will result us cross the date theshold for the next update
                if (parsedDate < DateTime.UtcNow.AddMinutes(5))
                    return DateTime.UtcNow.Add(_defaultCacheInterval);

                return parsedDate;
            }

            return null;
        }

        protected virtual async Task InitializeRepositoryAsync(IMetadataRepository repository)
        {
            var blobCacheKey = GetTocCacheKey(repository);

            var cachedToc = await _cache.GetStringAsync(blobCacheKey);

            MetadataBLOBPayload blob;

            DateTime? cacheUntil = null;

            if (cachedToc != null)
            {
                blob = JsonSerializer.Deserialize<MetadataBLOBPayload>(cachedToc);
                cacheUntil = GetCacheUntilTime(blob);
            }
            else
            {
                _log?.LogInformation($"BLOB for {repository.GetType().Name} not cached so loading from MDS...");

                try
                {
                    blob = await repository.GetBLOBAsync();
                }
                catch (Exception ex)
                {
                    _log?.LogError(ex, "Error getting BLOB from {0}", repository.GetType().Name);
                    throw;
                }

                _log?.LogInformation($"BLOB for {repository.GetType().Name} not cached so loading from MDS... Done.");

                cacheUntil = GetCacheUntilTime(blob);

                if (cacheUntil.HasValue)
                {
                    await _cache.SetStringAsync(
                        blobCacheKey,
                        JsonSerializer.Serialize(blob),
                        new DistributedCacheEntryOptions()
                        {
                            AbsoluteExpiration = cacheUntil
                        });
                }
            }

            foreach (var entry in blob.Entries)
            {
                if (!string.IsNullOrEmpty(entry.AaGuid)) //Only load FIDO2 entries
                {
                    try
                    {
                        await LoadTocEntryStatement(repository, blob, entry, cacheUntil);
                    }
                    catch (Exception ex)
                    {
                        _log?.LogError(ex, "Error getting statement from {0} for AAGUID '{1}'.\nTOC entry:\n{2} ", repository.GetType().Name, entry.AaGuid, JsonSerializer.Serialize(entry, new JsonSerializerOptions { WriteIndented = true }));
                    }
                }
            }
        }

        public virtual async Task InitializeAsync()
        {
            foreach (var repository in _repositories)
            {
                try
                {
                    await InitializeRepositoryAsync(repository);
                }
                catch (Exception ex)
                {
                    //Catch and log this as we don't want issues with external services to prevent app startup
                    _log?.LogCritical(ex, "Error initialising MDS client '{0}'", repository.GetType().Name);
                }
            }
            _initialized = true;
        }

        public virtual bool IsInitialized()
        {
            return _initialized;
        }
    }
}
