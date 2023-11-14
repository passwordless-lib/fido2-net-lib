namespace Fido2NetLib;

/// <summary>
/// Exception thrown when a new attestation comes from an authenticator with a current reported security issue.
/// </summary>
public class UndesiredMetadataStatusFido2VerificationException : Fido2VerificationException
{
    public UndesiredMetadataStatusFido2VerificationException(StatusReport statusReport) 
        : base($"Authenticator found with undesirable status. Was {statusReport.Status}")
    {
        StatusReport = statusReport;
    }

    /// <summary>
    /// Status report from the authenticator that caused the attestation to be rejected.
    /// </summary>
    public StatusReport StatusReport { get; }
}
