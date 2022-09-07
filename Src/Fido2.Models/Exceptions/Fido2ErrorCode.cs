using System;

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
    InvalidAuthenticatorResponse,
    InvalidAttestationResponse,
    InvalidAuthenticatorData,
    InvalidAttestedCredentialData,
    MissingAuthenticatorData,
    MissingAuthenticatorResponseChallenge,
    InvalidAuthenticatorResponseChallenge,
    NonUniqueCredentialId,
    AaGuidNotFound,
    UnimplementedAlgorithm
}
