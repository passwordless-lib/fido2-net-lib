using System;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// The events <see cref="Fido2"/> logs about registration and authentication ceremonies. Event IDs 1200-1299
/// belong to the ceremonies (1000-1199 are the metadata pipeline's). Credential IDs are logged base64url-encoded
/// and truncated, so an attacker-supplied value cannot inject line breaks or flood the log.
/// </summary>
internal static partial class CeremonyLog
{
    private const int MaxLoggedCredentialIdLength = 64;

    [LoggerMessage(EventId = 1200, Level = LogLevel.Information, Message = "Registered credential {CredentialId} for {RpId}: AAGUID {Aaguid}, attestation format {AttestationFormat}, attestation type {AttestationType}, backup eligible {BackupEligible}")]
    private static partial void RegistrationSucceeded(ILogger logger, string credentialId, string? rpId, Guid aaguid, string? attestationFormat, string? attestationType, bool backupEligible);

    [LoggerMessage(EventId = 1201, Level = LogLevel.Warning, Message = "Registration of credential {CredentialId} for {RpId} rejected: {ErrorCode}: {Reason}")]
    private static partial void RegistrationRejected(ILogger logger, string credentialId, string? rpId, Fido2ErrorCode errorCode, string reason);

    [LoggerMessage(EventId = 1202, Level = LogLevel.Information, Message = "Verified an assertion by credential {CredentialId} for {RpId}: sign count {SignCount}, user verified {UserVerified}, backed up {BackedUp}")]
    private static partial void AssertionSucceeded(ILogger logger, string credentialId, string? rpId, uint signCount, bool userVerified, bool backedUp);

    [LoggerMessage(EventId = 1203, Level = LogLevel.Warning, Message = "Assertion by credential {CredentialId} for {RpId} rejected: {ErrorCode}: {Reason}")]
    private static partial void AssertionRejected(ILogger logger, string credentialId, string? rpId, Fido2ErrorCode errorCode, string reason);

    [LoggerMessage(EventId = 1204, Level = LogLevel.Warning, Message = "RecheckMetadataStatusOnAssertion and/or MetadataConsistencyStrictness is enabled, but the assertion by credential {CredentialId} was verified without MakeAssertionParams.StoredAaGuid, so neither could check its metadata")]
    private static partial void MetadataRecheckSkipped(ILogger logger, string credentialId);

    [LoggerMessage(EventId = 1205, Level = LogLevel.Error, Message = "The {Ceremony} ceremony for credential {CredentialId} failed with an unexpected error")]
    private static partial void CeremonyFailed(ILogger logger, Exception exception, string ceremony, string credentialId);

    [LoggerMessage(EventId = 1206, Level = LogLevel.Warning, Message = "Metadata consistency ({Check}) mismatch for AAGUID {Aaguid}: {Detail}")]
    public static partial void MetadataConsistencyMismatchObserved(this ILogger logger, string check, Guid aaguid, string detail);

    [LoggerMessage(EventId = 1207, Level = LogLevel.Warning, Message = "Metadata consistency ({Check}) mismatch for AAGUID {Aaguid} is rejecting the ceremony: {Detail}")]
    public static partial void MetadataConsistencyMismatchBlocked(this ILogger logger, string check, Guid aaguid, string detail);

    public static void RegistrationSucceeded(this ILogger logger, string? rpId, RegisteredPublicKeyCredential credential)
    {
        RegistrationSucceeded(logger, FormatCredentialId(credential.Id), rpId, credential.AaGuid, credential.AttestationFormat, credential.AttestationType, credential.IsBackupEligible);
    }

    public static void RegistrationRejected(this ILogger logger, string? rpId, byte[]? credentialId, Fido2VerificationException exception)
    {
        RegistrationRejected(logger, FormatCredentialId(credentialId), rpId, exception.Code, exception.Message);
    }

    public static void AssertionSucceeded(this ILogger logger, string? rpId, VerifyAssertionResult result)
    {
        AssertionSucceeded(logger, FormatCredentialId(result.CredentialId), rpId, result.SignCount, result.IsUserVerified, result.IsBackedUp);
    }

    public static void AssertionRejected(this ILogger logger, string? rpId, byte[]? credentialId, Fido2VerificationException exception)
    {
        AssertionRejected(logger, FormatCredentialId(credentialId), rpId, exception.Code, exception.Message);
    }

    public static void MetadataRecheckSkipped(this ILogger logger, byte[]? credentialId)
    {
        MetadataRecheckSkipped(logger, FormatCredentialId(credentialId));
    }

    public static void CeremonyFailed(this ILogger logger, string ceremony, byte[]? credentialId, Exception exception)
    {
        CeremonyFailed(logger, exception, ceremony, FormatCredentialId(credentialId));
    }

    internal static string FormatCredentialId(byte[]? credentialId)
    {
        if (credentialId is null || credentialId.Length == 0)
            return "(none)";

        var encoded = System.Buffers.Text.Base64Url.EncodeToString(credentialId);
        return encoded.Length <= MaxLoggedCredentialIdLength ? encoded : string.Concat(encoded.AsSpan(0, MaxLoggedCredentialIdLength), "...");
    }
}
