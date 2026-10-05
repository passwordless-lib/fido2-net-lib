namespace Fido2NetLib.Exceptions;

[Flags]
public enum Fido2ErrorCode
{
    Unknown = 0,
    InvalidRpidHash,
    InvalidSignature,
    InvalidSignCount,
    UserVerificationRequirementNotMet,
    UserPresentFlagNotSet,
    UnexpectedExtensions,
    MissingStoredPublicKey,
    InvalidAttestation,
    InvalidAttestationObject,
    MalformedAttestationObject,
    AttestedCredentialDataFlagNotSet,
    UnknownAttestationType,
    MissingAttestationType,
    MalformedExtensionsDetected,
    UnexpectedExtensionsDetected,
    InvalidAssertionResponse,
    InvalidAttestationResponse,
    InvalidAttestedCredentialData,
    InvalidCredentialPublicKey,
    InvalidAuthenticatorResponse,
    MalformedAuthenticatorResponse,
    MissingAuthenticatorData,
    InvalidAuthenticatorData,
    MissingAuthenticatorResponseChallenge,
    InvalidAuthenticatorResponseChallenge,
    MissingAuthenticatorResponseOrigin,
    InvalidAuthenticatorResponseOrigin,
    NonUniqueCredentialId,
    AaGuidNotFound,
    UnimplementedAlgorithm,
    BackupEligibilityRequirementNotMet,
    BackupStateRequirementNotMet,
    CredentialAlgorithmRequirementNotMet,
    CrossOriginRequestNotAllowed,
    InvalidAuthenticatorResponseTopOrigin,
    InvalidBackupFlags,
    BackupEligibilityChanged,
    UnexpectedEnterpriseAttestation,
    MissingAttestationObject,
    InvalidCertificateChain,
    /// <summary>
    /// The authenticator's metadata status report is not one the configuration accepts (e.g. revoked or removed).
    /// </summary>
    UndesiredMetadataStatus,
    InvalidPaymentData,
    /// <summary>
    /// The credential's AAGUID is on the configured deny list.
    /// </summary>
    AaguidDenied,
    /// <summary>
    /// The credential's AAGUID is not on the configured allow list.
    /// </summary>
    AaguidNotAllowed,
    /// <summary>
    /// The BE flag is set, but the authenticator's metadata statement says (or, by omitting
    /// <c>multiDeviceCredentialSupport</c>, implies) that it does not support multi-device credentials.
    /// </summary>
    BackupEligibilityNotDeclaredInMetadata,
    /// <summary>
    /// The credential's AAGUID is on the configured allow list, but the attestation does not prove it: it is
    /// not a basic or attestation-CA attestation whose certificate chain validated against that model's
    /// metadata statement. See <see cref="Fido2Configuration.AaguidAllowListRequiresAttestation"/>.
    /// </summary>
    AaguidNotAttested,
    /// <summary>
    /// The credential's algorithm is not one of the algorithms the authenticator's own metadata statement
    /// declares it supports.
    /// </summary>
    AlgorithmNotDeclaredInMetadata,
    /// <summary>
    /// The credential ID is longer than the authenticator's own metadata statement declares it can generate.
    /// </summary>
    CredentialIdExceedsMetadataMaximum,
    /// <summary>
    /// The <c>credProps.rk</c> extension output claims a discoverable credential, but the authenticator's own
    /// metadata statement explicitly says it does not support discoverable credentials.
    /// </summary>
    DiscoverableCredentialNotDeclaredInMetadata,
    /// <summary>
    /// The client reported a transport for the credential that is not among the transports the authenticator's
    /// own metadata statement declares it supports.
    /// </summary>
    TransportNotDeclaredInMetadata,
    /// <summary>
    /// An authenticator-level extension output was returned for an extension the authenticator's own metadata
    /// statement does not declare support for.
    /// </summary>
    ExtensionNotDeclaredInMetadata,
    /// <summary>
    /// The BS flag is set on an assertion, but the authenticator's metadata statement says (or, by omitting
    /// <c>multiDeviceCredentialSupport</c>, implies) that it does not support multi-device credentials.
    /// </summary>
    BackupStateNotDeclaredInMetadata,
    /// <summary>
    /// The authenticator attachment modality reported for this assertion is not consistent with any transport
    /// the authenticator's own metadata statement declares it supports.
    /// </summary>
    AttachmentNotDeclaredInMetadata
}
