using System;

using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// The events the display-metadata sources log. Event IDs 1300-1399 belong to display metadata (1000-1199 are the
/// metadata pipeline's, 1200-1299 the ceremonies').
/// </summary>
internal static partial class DisplayMetadataLog
{
    [LoggerMessage(EventId = 1300, Level = LogLevel.Information, Message = "Downloaded Convenience Metadata Service document no. {Serial} from {Uri}: {EntryCount} authenticators")]
    public static partial void ConvenienceDocumentDownloaded(this ILogger logger, int? serial, Uri uri, int entryCount);

    [LoggerMessage(EventId = 1301, Level = LogLevel.Debug, Message = "Convenience Metadata Service document no. {Serial} is still current")]
    public static partial void ConvenienceDocumentNotModified(this ILogger logger, int? serial);

    [LoggerMessage(EventId = 1302, Level = LogLevel.Warning, Message = "Could not download the Convenience Metadata Service document from {Uri}; lookups use the last good copy until the next attempt at {RetryAt}")]
    public static partial void ConvenienceDocumentFailed(this ILogger logger, Exception exception, Uri uri, DateTimeOffset retryAt);

    [LoggerMessage(EventId = 1303, Level = LogLevel.Warning, Message = "The display metadata file {Path} does not exist; it provides no names or icons")]
    public static partial void LocalFileMissing(this ILogger logger, string path);

    [LoggerMessage(EventId = 1304, Level = LogLevel.Error, Message = "The display metadata file {Path} could not be read; it provides no names or icons")]
    public static partial void LocalFileUnreadable(this ILogger logger, Exception exception, string path);

    [LoggerMessage(EventId = 1305, Level = LogLevel.Warning, Message = "Display metadata source {Source} failed; answering from the other sources")]
    public static partial void SourceFailed(this ILogger logger, Exception exception, string source);
}
