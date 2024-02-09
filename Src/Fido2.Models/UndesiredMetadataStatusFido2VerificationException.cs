namespace Fido2NetLib;

/// <summary>
/// Exception thrown when a new attestation comes from an authenticator with a current reported security issue.
/// </summary>
public class UndesiredMetadataStatusFido2VerificationException(StatusReport statusReport)
    : Fido2VerificationException($"Authenticator found with undesirable status. Was {statusReport.Status}")
{
    /// <summary>
    /// Status report from the authenticator that caused the attestation to be rejected.
    /// </summary>
    public StatusReport StatusReport { get; } = statusReport;
}
