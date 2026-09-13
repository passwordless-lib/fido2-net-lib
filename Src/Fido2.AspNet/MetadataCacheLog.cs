using System;

using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// The events <see cref="DistributedCacheMetadataService"/> logs. Event IDs 1100-1199 belong to the metadata cache;
/// the repositories' own events are 1000-1099.
/// </summary>
internal static partial class MetadataCacheLog
{
    [LoggerMessage(EventId = 1100, Level = LogLevel.Error, Message = "Could not fetch metadata from {Repository}")]
    public static partial void MetadataFetchFailed(this ILogger logger, Exception exception, string repository);

    [LoggerMessage(EventId = 1101, Level = LogLevel.Warning, Message = "The metadata BLOB cached for {Repository} could not be read and will be fetched again")]
    public static partial void CachedBlobUnreadable(this ILogger logger, Exception exception, string repository);

    [LoggerMessage(EventId = 1102, Level = LogLevel.Debug, Message = "Using the cached metadata BLOB for {Repository}; it is current until {NextUpdate}")]
    public static partial void CachedBlobCurrent(this ILogger logger, string repository, DateTimeOffset? nextUpdate);

    [LoggerMessage(EventId = 1103, Level = LogLevel.Debug, Message = "The cached metadata BLOB for {Repository} was due for update at {NextUpdate}; fetching a fresh one")]
    public static partial void CachedBlobDue(this ILogger logger, string repository, DateTimeOffset? nextUpdate);

    [LoggerMessage(EventId = 1104, Level = LogLevel.Warning, Message = "Fetching a fresh metadata BLOB for {Repository} failed; continuing with the cached copy that was due for update")]
    public static partial void ContinuingWithDueCachedBlob(this ILogger logger, string repository);

    [LoggerMessage(EventId = 1105, Level = LogLevel.Information, Message = "Cached the metadata BLOB for {Repository} until {Expires}")]
    public static partial void BlobCached(this ILogger logger, string repository, DateTimeOffset expires);

    [LoggerMessage(EventId = 1106, Level = LogLevel.Warning, Message = "No metadata is available from {Repository}: the fetch failed and nothing is cached")]
    public static partial void NoMetadataAvailable(this ILogger logger, string repository);
}
