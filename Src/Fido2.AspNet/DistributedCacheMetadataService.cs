using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

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
        protected readonly ConcurrentDictionary<Guid, MetadataTOCPayloadEntry> _entries;

        protected const string CACHE_PREFIX = "DistributedCacheMetadataService";

        public DistributedCacheMetadataService(
            IEnumerable<IMetadataRepository> repositories,
            IDistributedCache cache,
            ILogger<DistributedCacheMetadataService> log)
        {
            _repositories = repositories.ToList();
            _cache = cache;
            _metadataStatements = new ConcurrentDictionary<Guid, MetadataStatement>();
            _entries = new ConcurrentDictionary<Guid, MetadataTOCPayloadEntry>();
            _log = log;
        }

        public virtual bool ConformanceTesting()
        {
            if (_repositories.First().GetType() == typeof(ConformanceMetadataRepository)) return true;
            return false;
        }

        public virtual MetadataTOCPayloadEntry GetEntry(Guid aaguid)
        {
            if (!IsInitialized()) throw new InvalidOperationException("MetadataService must be initialized");

            if (_entries.ContainsKey(aaguid))
            {
                var entry = _entries[aaguid];

                if (_metadataStatements.ContainsKey(aaguid))
                {
                    entry.MetadataStatement = _metadataStatements[aaguid];
                }

                return entry;
            }

            else return null;
        }

        protected virtual string GetTocCacheKey(IMetadataRepository repository)
        {
            return CACHE_PREFIX + ":" + repository.GetType().Name + ":TOC";
        }

        protected virtual string GetEntryCacheKey(IMetadataRepository repository, Guid aaGuid)
        {
            return CACHE_PREFIX + ":" + repository.GetType().Name + ":Entry:" + aaGuid.ToString();
        }

        protected virtual async Task LoadEntryStatement(IMetadataRepository repository, MetadataTOCPayloadEntry entry, DateTime? cacheUntil = null)
        {
            if (entry.AaGuid != null)
            {
                var cacheKey = GetEntryCacheKey(repository, Guid.Parse(entry.AaGuid));

                var cachedEntry = await _cache.GetStringAsync(cacheKey);
                if (cachedEntry != null)
                {
                    var statement = JsonConvert.DeserializeObject<MetadataStatement>(cachedEntry);
                    if (!string.IsNullOrWhiteSpace(statement.AaGuid)) _metadataStatements.TryAdd(Guid.Parse(statement.AaGuid), statement);
                }
                else
                {
                    _log?.LogInformation("Entry for {0}/{1} not cached so loading from MDS...", entry.AaGuid, entry.Aaid);

                    try
                    {
                        var statement = await repository.GetMetadataStatement(entry);

                        if (!string.IsNullOrWhiteSpace(statement.AaGuid))
                        {
                            _metadataStatements.TryAdd(Guid.Parse(statement.AaGuid), statement);

                            var statementJson = JsonConvert.SerializeObject(statement, Formatting.Indented);

                            if (cacheUntil.HasValue)
                            {
                                await _cache.SetStringAsync(cacheKey, statementJson, new DistributedCacheEntryOptions()
                                {
                                    AbsoluteExpiration = cacheUntil
                                });
                            }
                        }
                    }
                    catch(Exception ex)
                    {
                        _log?.LogError(ex, "Error getting MetadataStatement from {0} for AAGUID '{1}' ", repository.GetType().Name, entry.AaGuid);
                        throw;
                    }                    
                }
            }
        }

        private DateTime? GetCacheUntilTime(MetadataTOCPayload toc)
        {
            if (!string.IsNullOrWhiteSpace(toc?.NextUpdate)
                && DateTime.TryParseExact(
                    toc.NextUpdate,
                    new[] { "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss", "o" }, //Sould be ISO8601 date but allow for other ISO formats too
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                    out var parsedDate))
            {
                //NextUpdate is in the past to default to a useful number that will result us cross the date theshold for the next update
                if (parsedDate < DateTime.UtcNow.AddMinutes(5)) return DateTime.UtcNow.Add(_defaultCacheInterval);

                return parsedDate;
            }

            return null;
        }

        protected virtual async Task InitializeClient(IMetadataRepository repository)
        {
            var tocCacheKey = GetTocCacheKey(repository);

            var cachedToc = await _cache.GetStringAsync(tocCacheKey);

            MetadataTOCPayload toc;

            DateTime? cacheUntil = null;

            if (cachedToc != null)
            {
                toc = JsonConvert.DeserializeObject<MetadataTOCPayload>(cachedToc);
                cacheUntil = GetCacheUntilTime(toc);
            }
            else
            {
                _log?.LogInformation("TOC not cached so loading from MDS...");

                try
                {
                    toc = await repository.GetToc();
                }
                catch(Exception ex)
                {
                    _log?.LogError(ex, "Error getting TOC from {0}", repository.GetType().Name);
                    throw;
                }

                _log?.LogInformation("TOC not cached so loading from MDS... Done.");

                cacheUntil = GetCacheUntilTime(toc);

                if(cacheUntil.HasValue)
                {
                    await _cache.SetStringAsync(
                        tocCacheKey,
                        JsonConvert.SerializeObject(toc),
                        new DistributedCacheEntryOptions()
                        {
                            AbsoluteExpiration = cacheUntil
                        });
                }
            }

            foreach (var entry in toc.Entries)
            {
                if (!string.IsNullOrEmpty(entry.AaGuid))
                {
                    if(_entries.TryAdd(Guid.Parse(entry.AaGuid), entry))
                    {
                        //Load if it doesn't already exist
                        await LoadEntryStatement(repository, entry, cacheUntil);
                    }
                }
            }
        }

        public virtual async Task Initialize()
        {
            foreach(var client in _repositories)
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
