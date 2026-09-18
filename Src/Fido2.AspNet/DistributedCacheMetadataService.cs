using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// Caches the validated FIDO Metadata BLOB in an <see cref="IDistributedCache"/> (and an in-process
/// <see cref="IMemoryCache"/>) so it is not re-fetched on every request.
/// </summary>
/// <remarks>
/// Security note: the BLOB is written to the distributed cache as its parsed payload, without its JWS
/// signature, and is trusted as-is when read back -- it is not re-validated on read. Anything able to write to
/// the distributed cache can therefore plant arbitrary metadata (attestation roots, authenticator status
/// reports) that this service will trust. Treat the distributed cache as part of the trust boundary: it must be
/// access-controlled and not shared with untrusted workloads.
/// </remarks>
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
        return await GetEntryAsync(aaguid, attestationCertificates: null, cancellationToken);
    }

    public async Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaguid, X509Certificate2[] attestationCertificates, CancellationToken cancellationToken = default)
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
                        var matchingEntry = FindMatchingEntry(cachedPayload, aaguid, attestationCertificates);
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
