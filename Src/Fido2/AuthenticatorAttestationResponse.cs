using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// The AuthenticatorAttestationResponse interface represents the authenticator's response 
/// to a client’s request for the creation of a new public key credential.
/// It contains information about the new credential that can be used to identify it for later use, 
/// and metadata that can be used by the Relying Party to assess the characteristics of the credential during registration.
/// </summary>
public sealed class AuthenticatorAttestationResponse : AuthenticatorResponse
{
    private AuthenticatorAttestationResponse(AuthenticatorAttestationRawResponse raw, ParsedAttestationObject attestationObject)
        : base(raw.Response.ClientDataJson)
    {
        Raw = raw;
        AttestationObject = attestationObject;
    }

    public ParsedAttestationObject AttestationObject { get; }

    public AuthenticatorAttestationRawResponse Raw { get; }

    public static AuthenticatorAttestationResponse Parse(AuthenticatorAttestationRawResponse rawResponse)
    {
        if (rawResponse?.Response is null)
            throw new Fido2VerificationException("Expected rawResponse, got null");

        if (rawResponse.Response.AttestationObject is null || rawResponse.Response.AttestationObject.Length is 0)
            throw new Fido2VerificationException(Fido2ErrorMessages.MissingAttestationObject);

        // 8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure
        // to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
        CborMap cborAttestation;
        try
        {
            cborAttestation = (CborMap)CborObject.Decode(rawResponse.Response.AttestationObject);
        }
        catch (Exception ex)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestationObject, Fido2ErrorMessages.InvalidAttestationObject, ex);
        }

        var attestationObject = ParsedAttestationObject.FromCbor(cborAttestation);

        return new AuthenticatorAttestationResponse(rawResponse, attestationObject);
    }

    public async Task<RegisteredPublicKeyCredential> VerifyAsync(
        CredentialCreateOptions originalOptions,
        Fido2Configuration config,
        IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser,
        IMetadataService? metadataService,
        CancellationToken cancellationToken = default)
    {
        // https://www.w3.org/TR/webauthn/#registering-a-new-credential
        // 5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        // 6. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
        //    Note: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.
        //    Above handled in base class constructor

        // 7. Verify that the value of C.type is webauthn.create
        if (Type is not "webauthn.create")
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestationResponse, Fido2ErrorMessages.AttestationResponseTypeNotWebAuthnGet);

        // 8. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.
        // 9. Verify that the value of C.origin matches the Relying Party's origin.
        BaseVerify(config.FullyQualifiedOrigins, originalOptions.Challenge);

        if (Raw.Id is null || Raw.Id.Length == 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestationResponse, Fido2ErrorMessages.AttestationResponseIdMissing);

        if (Raw.Type != PublicKeyCredentialType.PublicKey)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestationResponse, Fido2ErrorMessages.AttestationResponseNotPublicKey);

        var authData = AttestationObject.AuthData;

        // 10. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
        byte[] clientDataHash = SHA256.HashData(Raw.Response.ClientDataJson);
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(originalOptions.Rp.Id));

        // 11. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt,
        //    the authenticator data authData, and the attestation statement attStmt.
        //    Handled in AuthenticatorAttestationResponse::Parse()

        // 12. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party
        if (!authData.RpIdHash.AsSpan().SequenceEqual(rpIdHash))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidRpidHash, Fido2ErrorMessages.InvalidRpidHash);

        // 13. Verify that the User Present bit of the flags in authData is set.
        if (!authData.UserPresent)
            throw new Fido2VerificationException(Fido2ErrorCode.UserPresentFlagNotSet, Fido2ErrorMessages.UserPresentFlagNotSet);

        // 14. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
        if (originalOptions.AuthenticatorSelection?.UserVerification is UserVerificationRequirement.Required && !authData.UserVerified)
            throw new Fido2VerificationException(Fido2ErrorCode.UserVerificationRequirementNotMet, Fido2ErrorMessages.UserVerificationRequirementNotMet);

        // 15. If the Relying Party uses the credential's backup eligibility to inform its user experience flows and/or policies, evaluate the BE bit of the flags in authData.
        if (authData.IsBackupEligible && config.BackupEligibleCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Disallowed ||
            !authData.IsBackupEligible && config.BackupEligibleCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Required)
            throw new Fido2VerificationException(Fido2ErrorCode.BackupEligibilityRequirementNotMet, Fido2ErrorMessages.BackupEligibilityRequirementNotMet);

        if (!authData.HasAttestedCredentialData)
            throw new Fido2VerificationException(Fido2ErrorCode.AttestedCredentialDataFlagNotSet, Fido2ErrorMessages.AttestedCredentialDataFlagNotSet);

        // 17. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
        if (!originalOptions.PubKeyCredParams.Any(a => authData.AttestedCredentialData.CredentialPublicKey.IsSameAlg(a.Alg)))
            throw new Fido2VerificationException(Fido2ErrorCode.CredentialAlgorithmRequirementNotMet, Fido2ErrorMessages.CredentialAlgorithmRequirementNotMet);

        // 18. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, 
        //     considering the client extension input values that were given as the extensions option in the create() call.  In particular, any extension identifier values 
        //     in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., 
        //     no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        // TODO?: Implement sort of like this: ClientExtensions.Keys.Any(x => options.extensions.contains(x);
        byte[]? devicePublicKeyResult = null;

        if (Raw.Extensions?.DevicePubKey is not null)
        {
            devicePublicKeyResult = await DevicePublicKeyRegistrationAsync(config, metadataService, Raw.Extensions, AttestationObject.AuthData, clientDataHash, cancellationToken).ConfigureAwait(false);
        }

        // 19. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt
        //     against the set of supported WebAuthn Attestation Statement Format Identifier values. 
        var verifier = AttestationVerifier.Create(AttestationObject.Fmt);

        // 20. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, 
        //     by using the attestation statement format fmt’s verification procedure given attStmt, authData
        //     and the hash of the serialized client data computed in step 7
        (var attType, var trustPath) = verifier.Verify(AttestationObject.AttStmt, AttestationObject.AuthData, clientDataHash);

        // 21. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys)
        //     for that attestation type and attestation statement format fmt, from a trusted source or from policy. 
        //     For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.

        MetadataBLOBPayloadEntry? metadataEntry = null;
        if (metadataService != null)
            metadataEntry = await metadataService.GetEntryAsync(authData.AttestedCredentialData.AaGuid, cancellationToken);

        // while conformance testing, we must reject any authenticator that we cannot get metadata for
        if (metadataService?.ConformanceTesting() is true && metadataEntry is null && attType != AttestationType.None && AttestationObject.Fmt is not "fido-u2f")
            throw new Fido2VerificationException(Fido2ErrorCode.AaGuidNotFound, "AAGUID not found in MDS test metadata");

        TrustAnchor.Verify(metadataEntry, trustPath);

        // 22. Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows:
        //     If self attestation was used, check if self attestation is acceptable under Relying Party policy.
        //     If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of acceptable trust anchors obtained in step 15.
        //     Otherwise, use the X.509 certificates returned by the verification procedure to verify that the attestation public key correctly chains up to an acceptable root certificate.

        // Check status reports for authenticator with undesirable status
        var latestStatusReport = metadataEntry?.GetLatestStatusReport();
        if (latestStatusReport != null && config.UndesiredAuthenticatorMetadataStatuses.Contains(latestStatusReport.Status))
        {
            throw new UndesiredMetadataStatusFido2VerificationException(latestStatusReport);
        }

        // 23. Verify that the credentialId is ≤ 1023 bytes.
        // Handled by AttestedCredentialData constructor

        // 24. Check that the credentialId is not yet registered to any other user. 
        //     If registration is requested for a credential that is already registered to a different user,
        //     the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration

        if (await isCredentialIdUniqueToUser(new IsCredentialIdUniqueToUserParams(authData.AttestedCredentialData.CredentialId, originalOptions.User), cancellationToken) is false)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.NonUniqueCredentialId, Fido2ErrorMessages.NonUniqueCredentialId);
        }

        // 25. If the attestation statement attStmt verified successfully and is found to be trustworthy,
        //     then register the new credential with the account that was denoted in the options.user passed to create(), 
        //     by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData,
        //     as appropriate for the Relying Party's system.

        // 26. If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above,
        //     the Relying Party SHOULD fail the registration ceremony.
        //     This implementation throws if the outputs are not trustworthy for a particular attestation type.

        return new RegisteredPublicKeyCredential
        {
            Type = Raw.Type,
            Id = authData.AttestedCredentialData.CredentialId,
            PublicKey = authData.AttestedCredentialData.CredentialPublicKey.GetBytes(),
            SignCount = authData.SignCount,
            // Transports = result of response.getTransports();
            IsBackupEligible = authData.IsBackupEligible,
            IsBackedUp = authData.IsBackedUp,
            AttestationObject = Raw.Response.AttestationObject,
            AttestationClientDataJson = Raw.Response.ClientDataJson,
            User = originalOptions.User,
            AttestationFormat = AttestationObject.Fmt,
            AaGuid = authData.AttestedCredentialData.AaGuid,
            DevicePublicKey = devicePublicKeyResult
        };
    }

    /// <summary>
    /// If the devicePubKey extension was included on a navigator.credentials.create() call, 
    /// then the below verification steps are performed in the context of this step of § 7.1 
    /// Registering a New Credential using these variables established therein: 
    /// credential, clientExtensionResults, authData, and hash. 
    /// Relying Party policy may specify whether a response without a devicePubKey is acceptable.
    /// </summary>
    /// <param name="clientExtensionResults"></param>
    /// <param name="authData"></param>
    /// <param name="hash"></param>
    /// <see cref="https://w3c.github.io/webauthn/#sctn-device-publickey-extension-verification-create"/> 
    private async Task<byte[]> DevicePublicKeyRegistrationAsync(
        Fido2Configuration config,
        IMetadataService? metadataService,
        AuthenticationExtensionsClientOutputs clientExtensionResults,
        AuthenticatorData authData,
        byte[] hash,
        CancellationToken cancellationToken)
    {
        // 1. Let attObjForDevicePublicKey be the value of the devicePubKey member of clientExtensionResults.
        var attObjForDevicePublicKey = clientExtensionResults.DevicePubKey!;

        // 2. Verify that attObjForDevicePublicKey is valid CBOR conforming to the syntax defined above and
        // perform CBOR decoding on it to extract the contained fields: aaguid, dpk, scope, nonce, fmt, attStmt.
        var devicePublicKeyAuthenticatorOutput = DevicePublicKeyAuthenticatorOutput.Parse(attObjForDevicePublicKey.AuthenticatorOutput);

        // 3. Verify that signature is a valid signature over the assertion signature input (i.e. authData and hash) by the device public key dpk. 
        if (!devicePublicKeyAuthenticatorOutput.DevicePublicKey.Verify(DataHelper.Concat(authData.ToByteArray(), hash), attObjForDevicePublicKey.Signature))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignature, Fido2ErrorMessages.InvalidSignature);

        // 4. Optionally, if attestation was requested and the Relying Party wishes to verify it, verify that attStmt is a correct attestation statement, conveying a valid attestation signature,
        // by using the attestation statement format fmt's verification procedure given attStmt.
        // https://www.w3.org/TR/webauthn/#defined-attestation-formats
        var verifier = AttestationVerifier.Create(devicePublicKeyAuthenticatorOutput.Fmt);

        // https://w3c.github.io/webauthn/#sctn-device-publickey-attestation-calculations
        (var attType, var trustPath) = verifier.Verify(devicePublicKeyAuthenticatorOutput.AttStmt, devicePublicKeyAuthenticatorOutput.GetAuthenticatorData(), devicePublicKeyAuthenticatorOutput.GetHash());

        // 5. Complete the steps from § 7.1 Registering a New Credential and, if those steps are successful,
        // store the aaguid, dpk, scope, fmt, attStmt values indexed to the credential.id in the user account.
        MetadataBLOBPayloadEntry? metadataEntry = null;
        if (metadataService != null)
            metadataEntry = await metadataService.GetEntryAsync(devicePublicKeyAuthenticatorOutput.AaGuid, cancellationToken);

        // while conformance testing, we must reject any authenticator that we cannot get metadata for
        if (metadataService?.ConformanceTesting() is true && metadataEntry is null && attType != AttestationType.None && devicePublicKeyAuthenticatorOutput.Fmt is not "fido-u2f")
            throw new Fido2VerificationException(Fido2ErrorCode.AaGuidNotFound, "AAGUID not found in MDS test metadata");

        TrustAnchor.Verify(metadataEntry, trustPath);

        // Check status reports for authenticator with undesirable status
        var latestStatusReport = metadataEntry?.GetLatestStatusReport();
        if (latestStatusReport != null && config.UndesiredAuthenticatorMetadataStatuses.Contains(latestStatusReport.Status))
        {
            throw new UndesiredMetadataStatusFido2VerificationException(latestStatusReport);
        }

        return devicePublicKeyAuthenticatorOutput.Encode();
    }

    /// <summary>
    /// The AttestationObject after CBOR parsing
    /// </summary>
    public sealed class ParsedAttestationObject
    {
        public ParsedAttestationObject(string fmt, CborMap attStmt, AuthenticatorData authData)
        {
            Fmt = fmt;
            AttStmt = attStmt;
            AuthData = authData;
        }

        public string Fmt { get; }

        public CborMap AttStmt { get; }

        public AuthenticatorData AuthData { get; }

        internal static ParsedAttestationObject FromCbor(CborMap cbor)
        {
            if (!(
                cbor["fmt"] is CborTextString fmt &&
                cbor["attStmt"] is CborMap attStmt &&
                cbor["authData"] is CborByteString authData))
            {
                throw new Fido2VerificationException(Fido2ErrorCode.MalformedAttestationObject, Fido2ErrorMessages.MalformedAttestationObject);
            }

            return new ParsedAttestationObject(
                fmt: fmt,
                attStmt: attStmt,
                authData: AuthenticatorData.Parse(authData)
            );
        }
    }
}
