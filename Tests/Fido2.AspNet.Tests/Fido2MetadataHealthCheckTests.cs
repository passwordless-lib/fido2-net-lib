using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Test;

/// <summary>
/// Covers <see cref="Fido2MetadataHealthCheck"/> and the status it reads from
/// <see cref="DistributedCacheMetadataService.GetRepositoryStatusAsync"/>: whether a BLOB is available, and whether
/// it is past its own <c>nextUpdate</c>.
/// </summary>
public class Fido2MetadataHealthCheckTests
{
    private static readonly DateTimeOffset s_now = new(2026, 9, 26, 12, 0, 0, TimeSpan.Zero);

    private sealed class FakeRepository(Func<Task<MetadataBLOBPayload>> getBlob) : IMetadataRepository
    {
        public int Calls { get; private set; }

        public Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            Calls++;
            return getBlob();
        }

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
            => Task.FromResult<MetadataStatement>(null);
    }

    private sealed class MockClock(DateTimeOffset time) : ISystemClock
    {
        public DateTimeOffset UtcNow { get; set; } = time;
    }

    private static MetadataBLOBPayload Payload(int number, DateTimeOffset? nextUpdate) => new()
    {
        Entries = [],
        NextUpdate = nextUpdate?.ToString("yyyy-MM-dd"),
        LegalHeader = "test",
        Number = number,
    };

    private static DistributedCacheMetadataService CreateService(IDistributedCache distributedCache = null, params IMetadataRepository[] repositories)
    {
        return new DistributedCacheMetadataService(
            repositories,
            distributedCache ?? new MemoryDistributedCache(Microsoft.Extensions.Options.Options.Create(new MemoryDistributedCacheOptions())),
            new MemoryCache(new MemoryCacheOptions()),
            NullLogger<DistributedCacheMetadataService>.Instance,
            new MockClock(s_now));
    }

    private static Task<HealthCheckResult> CheckAsync(IMetadataService service, TimeSpan? grace = null, CancellationToken cancellationToken = default)
    {
        var check = new Fido2MetadataHealthCheck(service, new MockClock(s_now)) { StaleGracePeriod = grace ?? Fido2MetadataHealthCheck.DefaultStaleGracePeriod };
        return check.CheckHealthAsync(new HealthCheckContext(), cancellationToken);
    }

    [Fact]
    public async Task LoadsTheBlobOnTheFirstCheckAndReportsItHealthyAsync()
    {
        // A process that has not handled a registration yet still reports on the metadata it would use.
        var repository = new FakeRepository(() => Task.FromResult(Payload(286, s_now.AddDays(10))));

        var result = await CheckAsync(CreateService(null, repository));

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal(1, repository.Calls);
        Assert.Equal("BLOB no. 286, next update 2026-10-06", result.Data[nameof(FakeRepository)]);
    }

    [Fact]
    public async Task IsUnhealthyWhenNoBlobIsAvailableAndSaysNothingAboutWhyAsync()
    {
        var repository = new FakeRepository(() => throw new InvalidOperationException("token=s3cret"));

        var result = await CheckAsync(CreateService(null, repository));

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains(nameof(FakeRepository), result.Description);
        Assert.DoesNotContain("s3cret", result.Description);
        Assert.Null(result.Exception);
        Assert.Equal("unavailable", result.Data[nameof(FakeRepository)]);
    }

    [Fact]
    public async Task IsDegradedWhenTheBlobIsWellPastItsNextUpdateAsync()
    {
        // The refresh keeps failing, so the service keeps serving the copy it has.
        var repository = new FakeRepository(() => Task.FromResult(Payload(280, s_now.AddDays(-10))));

        var result = await CheckAsync(CreateService(null, repository));

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("BLOB no. 280", result.Description);
        Assert.Contains("2026-09-16", result.Description);
    }

    [Fact]
    public async Task IsHealthyWithinTheGracePeriodAfterNextUpdateAsync()
    {
        var repository = new FakeRepository(() => Task.FromResult(Payload(285, s_now.AddDays(-1))));

        Assert.Equal(HealthStatus.Healthy, (await CheckAsync(CreateService(null, repository))).Status);
        Assert.Equal(HealthStatus.Degraded, (await CheckAsync(CreateService(null, repository), grace: TimeSpan.FromHours(1))).Status);
    }

    [Fact]
    public async Task ReportsACopyAnotherInstanceLeftInTheDistributedCacheAsync()
    {
        // A replica never fetches itself when the shared cache is current; it is healthy on that copy.
        var distributedCache = new MemoryDistributedCache(Microsoft.Extensions.Options.Options.Create(new MemoryDistributedCacheOptions()));
        await distributedCache.SetStringAsync(
            $"DistributedCacheMetadataService:V2:{nameof(FakeRepository)}:TOC",
            JsonSerializer.Serialize(Payload(286, s_now.AddDays(10))));
        var repository = new FakeRepository(() => throw new InvalidOperationException("unreachable"));

        var result = await CheckAsync(CreateService(distributedCache, repository));

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal(0, repository.Calls);
    }

    [Fact]
    public async Task IsHealthyForABlobWithoutANextUpdateAsync()
    {
        var repository = new FakeRepository(() => Task.FromResult(Payload(7, null)));

        var result = await CheckAsync(CreateService(null, repository));

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("BLOB no. 7, no next update", result.Data[nameof(FakeRepository)]);
    }

    [Fact]
    public async Task SaysSoWhenNoRepositoryIsConfiguredAsync()
    {
        var result = await CheckAsync(CreateService(null));

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("No metadata repository is configured.", result.Description);
    }

    [Fact]
    public async Task ReportsHealthyButUntrackedForAnotherMetadataServiceAsync()
    {
        var result = await CheckAsync(new Moq.Mock<IMetadataService>().Object);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains("only tracked", result.Description);
    }

    [Fact]
    public async Task StopsWaitingWhenTheCheckIsCancelledAsync()
    {
        var release = new TaskCompletionSource<MetadataBLOBPayload>();
        var service = CreateService(null, new FakeRepository(() => release.Task));
        using var cancellation = new CancellationTokenSource();

        var check = CheckAsync(service, cancellationToken: cancellation.Token);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => check);

        // The load carries on for everyone else.
        release.SetResult(Payload(1, s_now.AddDays(10)));
        Assert.Equal(HealthStatus.Healthy, (await CheckAsync(service)).Status);
    }

    [Fact]
    public async Task ReportsEveryRepositoryAsync()
    {
        var service = CreateService(null,
            new FakeRepository(() => Task.FromResult(Payload(1, s_now.AddDays(10)))),
            new ConformanceStandInRepository());

        var statuses = await service.GetRepositoryStatusAsync();

        Assert.Collection(statuses,
            s => Assert.Equal(new MetadataRepositoryStatus(nameof(FakeRepository), true, 1, new DateTimeOffset(2026, 10, 6, 0, 0, 0, TimeSpan.Zero)), s),
            s => Assert.Equal(new MetadataRepositoryStatus(nameof(ConformanceStandInRepository), false, null, null), s));
    }

    private sealed class ConformanceStandInRepository : IMetadataRepository
    {
        public Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default) => Task.FromResult<MetadataBLOBPayload>(null);

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
            => Task.FromResult<MetadataStatement>(null);
    }
}
