using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

public class DistributedCacheMetadataService : IMetadataService
{
    protected readonly IDistributedCache _distributedCache;
    protected readonly IMemoryCache _memoryCache;
    protected readonly ISystemClock _systemClock;

    protected readonly List<IMetadataRepository> _repositories;
    protected readonly ILogger<DistributedCacheMetadataService> _logger;

    protected readonly TimeSpan _defaultMemoryCacheInterval = TimeSpan.FromHours(1);
    protected readonly TimeSpan _nextUpdateBufferPeriod = TimeSpan.FromHours(25);
    protected readonly TimeSpan _defaultDistributedCacheInterval = TimeSpan.FromDays(8);

    protected const string CACHE_PREFIX = nameof(DistributedCacheMetadataService) + ":V2";

    public DistributedCacheMetadataService(
        IEnumerable<IMetadataRepository> repositories,
        IDistributedCache distributedCache,
        IMemoryCache memoryCache,
        ILogger<DistributedCacheMetadataService> logger,
        ISystemClock systemClock)
    {

        if (repositories == null)
            throw new ArgumentNullException(nameof(repositories));

        _repositories = repositories.ToList();
        _distributedCache = distributedCache;
        _memoryCache = memoryCache;
        _logger = logger;
        _systemClock = systemClock;
    }

    public virtual bool ConformanceTesting()
    {
        return _repositories.Any(o => o.GetType() == typeof(ConformanceMetadataRepository));
    }

    protected virtual string GetBlobCacheKey(IMetadataRepository repository)
    {
        return $"{CACHE_PREFIX}:{repository.GetType().Name}:TOC";
    }

    protected virtual DateTimeOffset? GetNextUpdateTimeFromPayload(MetadataBLOBPayload blob)
    {
        if (!string.IsNullOrWhiteSpace(blob?.NextUpdate)
            && DateTimeOffset.TryParseExact(
                blob.NextUpdate,
                new[] { "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss", "o" }, //Sould be ISO8601 date but allow for other ISO-like formats too
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var parsedDate))
        {
            return parsedDate;
        }

        return null;
    }

    protected virtual DateTimeOffset GetMemoryCacheAbsoluteExpiryTime(DateTimeOffset? nextUpdateTime)
    {
        var expiryTime = _systemClock.UtcNow.GetNextIncrement(_defaultMemoryCacheInterval);

        //Ensure that memory cache expiry time never exceeds the next update time from the service
        if (nextUpdateTime.HasValue && expiryTime > nextUpdateTime.Value)
            expiryTime = nextUpdateTime.Value;

        return expiryTime;
    }

    protected virtual DateTimeOffset GetDistributedCacheAbsoluteExpiryTime(DateTimeOffset? nextUpdatTime)
    {
        if (nextUpdatTime.HasValue)
        {
            if (nextUpdatTime > _systemClock.UtcNow)
                return nextUpdatTime.Value.Add(_defaultDistributedCacheInterval);
        }

        return _systemClock.UtcNow.Add(_defaultDistributedCacheInterval);
    }

    protected virtual async Task<MetadataBLOBPayload> GetRepositoryPayloadWithErrorHandling(IMetadataRepository repository, CancellationToken cancellationToken = default)
    {
        try
        {
            return await repository.GetBLOBAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not fetch metadata from {0}", repository.GetType().Name);
            return null;
        }
    }

    protected virtual async Task StoreDistributedCachedBlob(IMetadataRepository repository, MetadataBLOBPayload payload, CancellationToken cancellationToken = default)
    {
        await _distributedCache.SetStringAsync(
            GetBlobCacheKey(repository),
            JsonSerializer.Serialize(payload),
            new DistributedCacheEntryOptions()
            {
                AbsoluteExpiration = GetDistributedCacheAbsoluteExpiryTime(GetNextUpdateTimeFromPayload(payload))
            },
            cancellationToken);
    }

    protected virtual async Task<MetadataBLOBPayload> GetDistributedCachedBlob(IMetadataRepository repository, CancellationToken cancellationToken = default)
    {
        var cacheKey = GetBlobCacheKey(repository);

        var distributedCacheEntry = await _distributedCache.GetStringAsync(cacheKey, cancellationToken);
        if (distributedCacheEntry != null)
        {
            try
            {
                var cachedBlob = JsonSerializer.Deserialize<MetadataBLOBPayload>(distributedCacheEntry);
                var nextUpdateTime = GetNextUpdateTimeFromPayload(cachedBlob);

                //If the cache until time is in the past then update and return new data, otherwise return the cached value
                if (nextUpdateTime == null || nextUpdateTime.Value.Add(_nextUpdateBufferPeriod) < _systemClock.UtcNow)
                {
                    var payload = await GetRepositoryPayloadWithErrorHandling(repository, cancellationToken);
                    if (payload != null)
                    {
                        await StoreDistributedCachedBlob(repository, payload, cancellationToken);
                        return payload;
                    }
                }

                return cachedBlob;
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "{0}: Invalid BLOB value in distributed cache", nameof(DistributedCacheMetadataService));
            }
        }

        var repoBlob = await GetRepositoryPayloadWithErrorHandling(repository, cancellationToken);
        if (repoBlob != null)
        {
            await StoreDistributedCachedBlob(repository, repoBlob, cancellationToken);
        }

        return repoBlob;
    }

    protected virtual async Task<MetadataBLOBPayload> GetMemoryCachedPayload(IMetadataRepository repository, CancellationToken cancellationToken = default)
    {
        var cacheKey = GetBlobCacheKey(repository);

        var memCacheEntry = await _memoryCache.GetOrCreateAsync<MetadataBLOBPayload>(cacheKey, async memCacheEntry =>
        {
            var distributedCacheBlob = await GetDistributedCachedBlob(repository, cancellationToken);

            if (distributedCacheBlob != null)
            {
                var nextUpdateTime = GetNextUpdateTimeFromPayload(distributedCacheBlob);

                memCacheEntry.AbsoluteExpiration = GetMemoryCacheAbsoluteExpiryTime(nextUpdateTime);

                return distributedCacheBlob;
            }

            return null;
        });

        return memCacheEntry;
    }

    public async Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default)
    {
        var memCacheEntry = await _memoryCache.GetOrCreateAsync<MetadataBLOBPayloadEntry>(
            $"{CACHE_PREFIX}:{aaguid}",
            async entry =>
            {
                foreach (var repo in _repositories)
                {
                    var cachedPayload = await GetMemoryCachedPayload(repo, cancellationToken);
                    if (cachedPayload != null)
                    {
                        var matchingEntry = cachedPayload.Entries?.FirstOrDefault(o => o.AaGuid == aaguid);
                        if (matchingEntry != null)
                        {
                            entry.AbsoluteExpiration = GetMemoryCacheAbsoluteExpiryTime(GetNextUpdateTimeFromPayload(cachedPayload));
                            return matchingEntry;
                        }
                    }
                }

                return null;

            });

        return memCacheEntry;
    }
}
