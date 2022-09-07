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
    AaGuidNotFound
}
