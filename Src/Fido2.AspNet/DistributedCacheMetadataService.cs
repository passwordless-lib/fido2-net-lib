using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

public class DistributedCacheMetadataService : IMetadataService, IMetadataServiceAttestationCertificateLookup
{
    protected readonly IDistributedCache _distributedCache;
    protected readonly IMemoryCache _memoryCache;
    protected readonly ISystemClock _systemClock;

    protected readonly List<IMetadataRepository> _repositories;
    protected readonly ILogger<DistributedCacheMetadataService> _logger;

    /// <summary>
    /// Default in-process memory cache interval, capped by the BLOB's NextUpdate value if sooner.
    /// </summary>
    protected readonly TimeSpan _defaultMemoryCacheInterval = TimeSpan.FromHours(1);

    /// <summary>
    /// Grace period after NextUpdate before a refetch is attempted, to avoid hammering the MDS endpoint
    /// the moment NextUpdate elapses (the new BLOB may not be published exactly on time).
    /// FIDO Alliance does not publish a specific rate limit; their own guidance
    /// (https://fidoalliance.org/metadata/) is to fetch the BLOB about once a month and cache it, since
    /// MDS data changes infrequently. This buffer is a conservative allowance, not a documented requirement.
    /// </summary>
    protected readonly TimeSpan _nextUpdateBufferPeriod = TimeSpan.FromHours(24);

    /// <summary>
    /// Default distributed cache interval used when the BLOB has no NextUpdate value. Aligned with FIDO
    /// Alliance's published guidance to fetch the BLOB about once a month (https://fidoalliance.org/metadata/).
    /// </summary>
    protected readonly TimeSpan _defaultDistributedCacheInterval = TimeSpan.FromDays(30);

    protected const string CACHE_PREFIX = nameof(DistributedCacheMetadataService) + ":V2";

    public DistributedCacheMetadataService(
        IEnumerable<IMetadataRepository> repositories,
        IDistributedCache distributedCache,
        IMemoryCache memoryCache,
        ILogger<DistributedCacheMetadataService> logger,
        ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(repositories);

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
                new[] { "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss", "o" }, // Should be ISO8601 date but allow for other ISO-like formats too
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

    /// <summary>
    /// Gets the absolute expiry time for the distributed cache.
    /// </summary>
    /// <param name="nextUpdateTime">The next update time from the MDS BLOB payload.</param>
    /// <returns>The absolute expiry time for the cached data.</returns>
    /// <remarks>
    /// When the BLOB has a NextUpdate value, the distributed cache expires at NextUpdate + <see cref="_nextUpdateBufferPeriod"/>,
    /// allowing multiple servers to share the cached BLOB without each independently refetching the moment NextUpdate passes.
    /// Otherwise it falls back to <see cref="_defaultDistributedCacheInterval"/>.
    /// </remarks>
    protected virtual DateTimeOffset GetDistributedCacheAbsoluteExpiryTime(DateTimeOffset? nextUpdateTime)
    {
        if (nextUpdateTime.HasValue)
        {
            return nextUpdateTime.Value.Add(_nextUpdateBufferPeriod);
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

    /// <summary>
    /// Gets the repository's BLOB from the in-process cache, filling it from the distributed cache (and behind
    /// that, the repository) on a miss.
    /// </summary>
    /// <remarks>
    /// A fetch that yields nothing is not cached: the memory cache stores null values, and one stored without
    /// an expiry would stand in for the BLOB until the process restarted, so a transient outage on the first
    /// lookup would silently switch metadata validation off for good. Leaving the miss uncached means the next
    /// lookup tries again.
    /// </remarks>
    protected virtual async Task<MetadataBLOBPayload> GetMemoryCachedPayload(IMetadataRepository repository, CancellationToken cancellationToken = default)
    {
        var cacheKey = GetBlobCacheKey(repository);

        if (_memoryCache.TryGetValue(cacheKey, out MetadataBLOBPayload cachedBlob))
            return cachedBlob;

        var distributedCacheBlob = await GetDistributedCachedBlob(repository, cancellationToken);

        if (distributedCacheBlob is null)
            return null;

        _memoryCache.Set(cacheKey, distributedCacheBlob, GetMemoryCacheAbsoluteExpiryTime(GetNextUpdateTimeFromPayload(distributedCacheBlob)));

        return distributedCacheBlob;
    }

    public async Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default)
    {
        return await GetEntryAsync(aaguid, attestationCertificates: null, cancellationToken);
    }

    /// <remarks>
    /// A lookup that found no entry is cached (as null) only when at least one repository actually supplied a
    /// BLOB to search, and then only until the earliest of those BLOBs expires, so an AAGUID that is genuinely
    /// unknown is not looked up again on every registration, while one that could not be looked up because no
    /// BLOB was available is retried next time.
    /// </remarks>
    public async Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaguid, X509Certificate2[] attestationCertificates, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{CACHE_PREFIX}:{aaguid}";

        if (_memoryCache.TryGetValue(cacheKey, out MetadataBLOBPayloadEntry cachedEntry))
            return cachedEntry;

        DateTimeOffset? missExpiry = null;

        foreach (var repo in _repositories)
        {
            var cachedPayload = await GetMemoryCachedPayload(repo, cancellationToken);
            if (cachedPayload is null)
                continue;

            var payloadExpiry = GetMemoryCacheAbsoluteExpiryTime(GetNextUpdateTimeFromPayload(cachedPayload));

            var matchingEntry = FindMatchingEntry(cachedPayload, aaguid, attestationCertificates);
            if (matchingEntry != null)
            {
                _memoryCache.Set(cacheKey, matchingEntry, payloadExpiry);
                return matchingEntry;
            }

            if (missExpiry is null || payloadExpiry < missExpiry.Value)
                missExpiry = payloadExpiry;
        }

        if (missExpiry.HasValue)
            _memoryCache.Set<MetadataBLOBPayloadEntry>(cacheKey, null, missExpiry.Value);

        return null;
    }

    /// <summary>
    /// Finds the entry matching <paramref name="aaguid"/>, falling back to matching
    /// <paramref name="attestationCertificates"/> against entries identified only by
    /// <see cref="MetadataBLOBPayloadEntry.AttestationCertificateKeyIdentifiers"/> (e.g. FIDO U2F authenticators,
    /// which have neither an AAID nor an AAGUID in MDS).
    /// </summary>
    protected virtual MetadataBLOBPayloadEntry FindMatchingEntry(MetadataBLOBPayload payload, Guid aaguid, X509Certificate2[] attestationCertificates)
    {
        if (payload.Entries is null)
            return null;

        var matchingEntry = payload.Entries.FirstOrDefault(o => o.AaGuid == aaguid);
        if (matchingEntry != null)
            return matchingEntry;

        if (attestationCertificates is not { Length: > 0 })
            return null;

        return payload.Entries.FirstOrDefault(entry =>
            entry.AaGuid is null &&
            attestationCertificates.Any(entry.MatchesAttestationCertificate));
    }
}
