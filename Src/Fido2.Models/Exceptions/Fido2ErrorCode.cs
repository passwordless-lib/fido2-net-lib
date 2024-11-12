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
    InvalidAuthenticatorResponse,
    MalformedAuthenticatorResponse,
    MissingAuthenticatorData,
    InvalidAuthenticatorData,
    MissingAuthenticatorResponseChallenge,
    InvalidAuthenticatorResponseChallenge,
    NonUniqueCredentialId,
    AaGuidNotFound,
    UnimplementedAlgorithm,
    BackupEligibilityRequirementNotMet,
    BackupStateRequirementNotMet,
    CredentialAlgorithmRequirementNotMet
}
