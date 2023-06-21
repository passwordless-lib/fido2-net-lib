using Fido2NetLib.Objects;

namespace Fido2NetLib.Exceptions;

internal static class Fido2ErrorMessages
{
    public static readonly string InvalidSignature                       = "Signature does not match";
    public static readonly string InvalidRpidHash                        = "RPID hash does not match";
    public static readonly string UnexpectedExtensionsDetected           = "Extensions flag not present, but extensions detected";
    public static readonly string MalformedExtensionsDetected            = "Extensions flag present, malformed extensions detected";
    public static readonly string SignCountIsLessThanSignatureCounter    = "SignCount must be greater than the current SignatureCounter";
    public static readonly string UserVerificationRequirementNotMet      = "User Verified flag not set in authenticator data and user verification was required";
    public static readonly string MissingStoredPublicKey                 = "Stored public key is null or empty";
    public static readonly string MissingAttestationObject               = "Missing AttestationObject";
    public static readonly string InvalidAttestationObject               = "Invalid AttestationObject CBOR data";
    public static readonly string MalformedAttestationObject             = "Malformed AttestationObject";
    public static readonly string UserPresentFlagNotSet                  = "User Present flag not set in authenticator data";
    public static readonly string InvalidCertificateChain                = "Invalid certificate chain";
    public static readonly string UserHandleIsEmpty                      = "UserHandle was empty DOMString. It should either be null or have a value.";
    public static readonly string InvalidAttestedCredentialData_TooShort = "Not enough bytes to be a valid AttestedCredentialData";
    public static readonly string InvalidAttestedCredentialData_CredentialIdTooLong = "CredentialId too many bytes";
    public static readonly string MissingAuthenticatorResponseChallange  = "Authenticator response challenge may not be null";
    public static readonly string InvalidAuthenticatorResponseChallenge  = "Authenticator response challenge does not match original challenge";
    public static readonly string AttestedCredentialDataFlagNotSet       = "Attestation flag not set on attestation data";
    public static readonly string MissingAuthenticatorData               = "Authenticator data may not be null";
    public static readonly string InvalidAuthenticatorData_TooShort      = $"Authenticator data is less than the minimum structure length of {AuthenticatorData.MinLength}";
    public static readonly string InvalidCoseAlgorithmValue              = "Unrecognized COSE algorithm value";
    public static readonly string BackupEligibilityRequirementNotMet     = "Backup eligibility does not match policy requirement";
    public static readonly string BackupStateRequirementNotMet           = "Backup state does not match policy requirement";
    public static readonly string CredentialAlgorithmRequirementNotMet   = "Credential algorithm does not match policy requirement";
    public static readonly string NonUniqueCredentialId                  = "CredentialId is not unique to this user";
    public static readonly string MissingAttestationType                 = "Missing attestation type";
    public static readonly string InvalidAttestationCertSubject          = "Invalid attestation cert subject";
    public static readonly string InvalidDevicePublicKeyAttestation      = "Invalid devicePublicKey attestation";
    public static readonly string NonUniqueDevicePublicKey               = "More than one devicePublicKey match";
    public static readonly string AssertionResponseNotPublicKey          = "AssertionResponse type must be public-key";
    public static readonly string AssertionResponseIdMissing             = "AssertionResponse Id is missing";
    public static readonly string AssertionResponseRawIdMissing          = "AssertionResponse RawId is missing";
    public static readonly string CredentialIdNotInAllowedCredentials    = "Credential ID not in allowed credentials";
    public static readonly string UserHandleNotOwnerOfPublicKey          = "User is not owner of the public key identified by the credential id";
    public static readonly string AssertionTypeNotWebAuthnGet            = "AssertionResponse type must be webauthn.get";

    public static readonly string UnimplementedAlgorithm_Ecdaa_Packed    = "ECDAA support for packed attestation is not yet implemented";
    public static readonly string UnimplementedAlgorithm_Ecdaa_Tpm       = "ECDAA support for TPM attestation is not yet implemented";

    public static readonly string MalformedX5c_AppleAttestation          = "Malformed x5c in Apple attestation";
    public static readonly string MalformedX5c_AndroidKeyAttestation     = "Malformed x5c in android-key attestation";
    public static readonly string MalformedX5c_FidoU2fAttestation        = "Malformed x5c in fido-u2f attestation";
    public static readonly string MalformedX5c_PackedAttestation         = "Malformed x5c in packed attestation";
    public static readonly string MalformedX5c_TpmAttestation            = "Malformed x5c in TPM attestation";

    public static readonly string InvalidAndroidKeyAttestationAlgorithm  = "Invalid android-key attestation algorithm";
    public static readonly string InvalidPackedAttestationAlgorithm      = "Invalid packed attestation algorithm";
    public static readonly string InvalidTpmAttestationAlgorithm         = "Invalid TPM attestation algorithm";

    public static readonly string MissingPackedAttestationStatement      = "Attestation format packed must have attestation statement";
    public static readonly string MissingAndroidKeyAttestationStatement  = "Attestation format android-key must have attestation statement";

    public static readonly string InvalidAndroidKeyAttestationSignature  = "Invalid android-key attestation signature";
    public static readonly string InvalidFidoU2fAttestationSignature     = "Invalid fido-u2f attestation signature";
    public static readonly string InvalidPackedAttestationSignature      = "Invalid packed attestation signature";
    public static readonly string InvalidTpmAttestationSignature         = "Invalid TPM attestation signature";
}
