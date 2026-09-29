using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Internal;

namespace Fido2NetLib;

/// <summary>
/// Reports whether the FIDO Metadata Service BLOB(s) <see cref="DistributedCacheMetadataService"/> verifies
/// attestations against are available and current. Registered by <c>AddFido2MetadataHealthCheck()</c>.
/// </summary>
/// <remarks>
/// <para>
/// Each check asks the service which BLOB it is serving, loading it if nothing has yet -- so a process that has
/// not handled a registration still reports on the metadata it would use, and a replica served from the
/// distributed cache reports on that copy.
/// </para>
/// <list type="bullet">
/// <item><description><see cref="HealthStatus.Unhealthy"/>: a repository has no BLOB at all (its fetch failed and
/// nothing is cached), so metadata checks are not happening for it.</description></item>
/// <item><description><see cref="HealthStatus.Degraded"/>: a BLOB is more than <see cref="StaleGracePeriod"/> past its
/// own <c>nextUpdate</c>, meaning refreshes are failing and an old copy is being kept. Verification still works
/// against it, but revocations published since are not seen.</description></item>
/// </list>
/// <para>
/// The description names repositories, BLOB numbers and dates only; why a fetch failed is in the logs
/// (<c>DistributedCacheMetadataService</c>'s fetch-failure event), not in health output that may be publicly exposed.
/// </para>
/// </remarks>
/// <param name="metadataService">The metadata service to report on.</param>
/// <param name="systemClock">The clock staleness is judged against.</param>
public sealed class Fido2MetadataHealthCheck(IMetadataService metadataService, ISystemClock systemClock) : IHealthCheck
{
    /// <summary>
    /// The default <see cref="StaleGracePeriod"/>: two days. The service only tries to replace a BLOB a day after
    /// its <c>nextUpdate</c>, and FIDO Alliance does not always publish exactly on time.
    /// </summary>
    public static readonly TimeSpan DefaultStaleGracePeriod = TimeSpan.FromDays(2);

    /// <summary>
    /// How long past a BLOB's own <c>nextUpdate</c> it may still be served before the check reports
    /// <see cref="HealthStatus.Degraded"/>.
    /// </summary>
    public TimeSpan StaleGracePeriod { get; init; } = DefaultStaleGracePeriod;

    /// <inheritdoc/>
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        if (metadataService is not DistributedCacheMetadataService distributedCacheMetadataService)
            return HealthCheckResult.Healthy("Metadata freshness is only tracked for DistributedCacheMetadataService.");

        var statuses = await distributedCacheMetadataService.GetRepositoryStatusAsync(cancellationToken);

        var now = systemClock.UtcNow;
        var unavailable = new List<string>();
        var stale = new List<string>();
        var data = new Dictionary<string, object>(StringComparer.Ordinal);

        foreach (var status in statuses)
        {
            if (!status.Available)
            {
                unavailable.Add(status.Repository);
                data[status.Repository] = "unavailable";
                continue;
            }

            data[status.Repository] = status.NextUpdate is { } nextUpdate
                ? $"BLOB no. {status.BlobNumber}, next update {nextUpdate:yyyy-MM-dd}"
                : $"BLOB no. {status.BlobNumber}, no next update";

            if (status.NextUpdate is { } due && now - due > StaleGracePeriod)
                stale.Add($"{status.Repository} is serving BLOB no. {status.BlobNumber}, due for replacement on {due:yyyy-MM-dd}");
        }

        if (unavailable.Count > 0)
            return HealthCheckResult.Unhealthy($"No metadata BLOB is available from {string.Join(", ", unavailable)}; metadata checks are not being applied.", data: data);

        if (stale.Count > 0)
            return HealthCheckResult.Degraded(string.Join("; ", stale), data: data);

        return HealthCheckResult.Healthy(statuses.Count == 0 ? "No metadata repository is configured." : null, data);
    }
}
