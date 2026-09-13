using System;

using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// The events the metadata repositories log. Event IDs 1000-1099 belong to the metadata pipeline; the
/// verification hot path does not log, since every failure there surfaces as a <see cref="Fido2VerificationException"/>.
/// </summary>
internal static partial class MetadataLog
{
    // Fido2MetadataServiceRepository: 1000-1009

    [LoggerMessage(EventId = 1000, Level = LogLevel.Debug, Message = "Fetching the metadata BLOB from {Uri} (conditional: {Conditional})")]
    public static partial void FetchingBlob(this ILogger logger, Uri? uri, bool conditional);

    [LoggerMessage(EventId = 1001, Level = LogLevel.Debug, Message = "The metadata BLOB at {Uri} has not changed since the last fetch; reusing the cached copy")]
    public static partial void BlobNotModified(this ILogger logger, Uri? uri);

    [LoggerMessage(EventId = 1002, Level = LogLevel.Information, Message = "Downloaded the metadata BLOB from {Uri} ({Bytes} bytes)")]
    public static partial void BlobDownloaded(this ILogger logger, Uri? uri, long bytes);

    [LoggerMessage(EventId = 1003, Level = LogLevel.Warning, Message = "The metadata service at {Uri} answered {StatusCode}; retrying in {Delay} (attempt {Attempt} of {MaxAttempts})")]
    public static partial void BlobFetchThrottled(this ILogger logger, Uri? uri, int statusCode, TimeSpan delay, int attempt, int maxAttempts);

    [LoggerMessage(EventId = 1004, Level = LogLevel.Debug, Message = "The metadata BLOB signature verified ({Alg}; {ChainLength} certificate(s) in x5c)")]
    public static partial void BlobSignatureVerified(this ILogger logger, string alg, int chainLength);

    [LoggerMessage(EventId = 1005, Level = LogLevel.Debug, Message = "The platform did not trust the BLOB signing chain; checking it against the pinned metadata root")]
    public static partial void BlobChainCheckedAgainstPinnedRoot(this ILogger logger);

    [LoggerMessage(EventId = 1006, Level = LogLevel.Debug, Message = "Checking {Subject} against the CRL at {Cdp}")]
    public static partial void CheckingBlobCertificateRevocation(this ILogger logger, string subject, string cdp);

    [LoggerMessage(EventId = 1007, Level = LogLevel.Information, Message = "Metadata BLOB no. {Number} accepted: {EntryCount} entries, next update {NextUpdate}")]
    public static partial void BlobAccepted(this ILogger logger, long number, int entryCount, string? nextUpdate);

    // FileSystemMetadataRepository: 1010-1019

    [LoggerMessage(EventId = 1010, Level = LogLevel.Warning, Message = "The metadata directory {Directory} does not exist; no metadata statements were loaded")]
    public static partial void MetadataDirectoryMissing(this ILogger logger, string directory);

    [LoggerMessage(EventId = 1011, Level = LogLevel.Debug, Message = "Loaded the metadata statement for {AaGuid} from {File}")]
    public static partial void MetadataStatementLoaded(this ILogger logger, Guid aaGuid, string file);

    [LoggerMessage(EventId = 1012, Level = LogLevel.Warning, Message = "The metadata statement in {File} has no AAGUID, so it cannot be matched to an authenticator; skipped")]
    public static partial void MetadataStatementWithoutAaGuid(this ILogger logger, string file);

    [LoggerMessage(EventId = 1013, Level = LogLevel.Information, Message = "Loaded {Count} metadata statement(s) from {Directory}")]
    public static partial void MetadataStatementsLoaded(this ILogger logger, int count, string directory);

    // ConformanceMetadataRepository: 1020-1029

    [LoggerMessage(EventId = 1020, Level = LogLevel.Information, Message = "The conformance tool provisioned {Count} metadata endpoint(s) for {Origin}")]
    public static partial void ConformanceEndpointsReceived(this ILogger logger, int count, string origin);

    [LoggerMessage(EventId = 1021, Level = LogLevel.Warning, Message = "The metadata BLOB from {Url} was rejected and skipped")]
    public static partial void ConformanceBlobRejected(this ILogger logger, Exception exception, string url);

    [LoggerMessage(EventId = 1022, Level = LogLevel.Information, Message = "Combined {EntryCount} entries from {BlobCount} conformance BLOB(s)")]
    public static partial void ConformanceBlobsCombined(this ILogger logger, int entryCount, int blobCount);
}
