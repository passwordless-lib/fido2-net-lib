using System;
using System.Collections.Generic;
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
/// The AuthenticatorAssertionResponse interface represents an authenticator's response to a client’s request for generation of a new authentication assertion given the Relying Party's challenge and optional list of credentials it is aware of.
/// This response contains a cryptographic signature proving possession of the credential private key, and optionally evidence of user consent to a specific transaction.
/// </summary>
public sealed class AuthenticatorAssertionResponse : AuthenticatorResponse
{
    private readonly AuthenticatorAssertionRawResponse _raw;

    private AuthenticatorAssertionResponse(AuthenticatorAssertionRawResponse raw, AuthenticatorData authenticatorData)
        : base(raw.Response.ClientDataJson)
    {
        _raw = raw;
        AuthenticatorData = authenticatorData;
    }

    internal AuthenticatorAssertionRawResponse Raw => _raw; // accessed in Verify()

    public AuthenticatorData AuthenticatorData { get; init; }

    public ReadOnlySpan<byte> Signature => _raw.Response.Signature;

    public byte[]? UserHandle => _raw.Response.UserHandle;

    public byte[]? AttestationObject => _raw.Response.AttestationObject;

    public static AuthenticatorAssertionResponse Parse(AuthenticatorAssertionRawResponse rawResponse)
    {
        return new AuthenticatorAssertionResponse(
            raw: rawResponse,
            authenticatorData: AuthenticatorData.Parse(rawResponse.Response.AuthenticatorData)
        );
    }

    /// <summary>
    /// Implements algorithm from https://www.w3.org/TR/webauthn/#verifying-assertion
    /// </summary>
    /// <param name="options">The assertionoptions that was sent to the client</param>
    /// <param name="fullyQualifiedExpectedOrigins">
    /// The expected fully qualified server origins, used to verify that the signature is sent to the expected server
    /// </param>
    /// <param name="storedPublicKey">The stored public key for this CredentialId</param>
    /// <param name="storedSignatureCounter">The stored counter value for this CredentialId</param>
    /// <param name="isUserHandleOwnerOfCredId">A function that returns <see langword="true"/> if user handle is owned by the credential ID</param>
    /// <param name="cancellationToken"></param>
    public async Task<VerifyAssertionResult> VerifyAsync(
        AssertionOptions options,
        Fido2Configuration config,
        byte[] storedPublicKey,
        List<byte[]> storedDevicePublicKeys,
        uint storedSignatureCounter,
        IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredId,
        IMetadataService? metadataService,
        CancellationToken cancellationToken = default)
    {
        BaseVerify(config.FullyQualifiedOrigins, options.Challenge);

        if (Raw.Type != PublicKeyCredentialType.PublicKey)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, Fido2ErrorMessages.AssertionResponseNotPublicKey);

        if (Raw.Id is null)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, Fido2ErrorMessages.AssertionResponseIdMissing);

        if (Raw.RawId is null)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, Fido2ErrorMessages.AssertionResponseRawIdMissing);

        // 5. If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        if (options.AllowCredentials != null && options.AllowCredentials.Any())
        {
            // might need to transform x.Id and raw.id as described in https://www.w3.org/TR/webauthn/#publickeycredential
            if (!options.AllowCredentials.Any(x => x.Id.SequenceEqual(Raw.Id)))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, Fido2ErrorMessages.CredentialIdNotInAllowedCredentials);
        }

        // 6. Identify the user being authenticated and verify that this user is the owner of the public key credential source credentialSource identified by credential.id
        if (UserHandle != null)
        {
            if (UserHandle.Length is 0)
                throw new Fido2VerificationException(Fido2ErrorMessages.UserHandleIsEmpty);

            if (await isUserHandleOwnerOfCredId(new IsUserHandleOwnerOfCredentialIdParams(Raw.Id, UserHandle), cancellationToken) is false)
            {
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, Fido2ErrorMessages.UserHandleNotOwnerOfPublicKey);
            }
        }

        // 7. Let cData, authData and sig denote the value of credential’s response's clientDataJSON, authenticatorData, and signature respectively.
        //var cData = Raw.Response.ClientDataJson;
        var authData = AuthenticatorData;
        //var sig = Raw.Response.Signature;

        // 8. Let JSONtext be the result of running UTF-8 decode on the value of cData.
        // var JSONtext = Encoding.UTF8.GetBytes(cData.ToString());

        // 10. Verify that the value of C.type is the string webauthn.get.
        if (Type is not "webauthn.get")
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, Fido2ErrorMessages.AssertionResponseTypeNotWebAuthnGet);

        // 11. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        // 12. Verify that the value of C.origin matches the Relying Party's origin.
        // Both handled in BaseVerify

        // 13. Verify that the rpIdHash in aData is the SHA - 256 hash of the RP ID expected by the Relying Party.

        // https://www.w3.org/TR/webauthn/#sctn-appid-extension
        // FIDO AppID Extension:
        // If true, the AppID was used and thus, when verifying an assertion, the Relying Party MUST expect the rpIdHash to be the hash of the AppID, not the RP ID.
        var rpid = Raw.Extensions?.AppID ?? false ? options.Extensions?.AppID : options.RpId;
        byte[] hashedRpId = SHA256.HashData(Encoding.UTF8.GetBytes(rpid ?? string.Empty));
        byte[] hash = SHA256.HashData(Raw.Response.ClientDataJson);

        if (!authData.RpIdHash.SequenceEqual(hashedRpId))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidRpidHash, Fido2ErrorMessages.InvalidRpidHash);

        // 14. Verify that the UP bit of the flags in authData is set.
        if (!authData.UserPresent)
            throw new Fido2VerificationException(Fido2ErrorCode.UserPresentFlagNotSet, Fido2ErrorMessages.UserPresentFlagNotSet);

        // 15. If the Relying Party requires user verification for this assertion, verify that the UV bit of the flags in authData is set.
        if (options.UserVerification is UserVerificationRequirement.Required && !authData.UserVerified)
            throw new Fido2VerificationException(Fido2ErrorCode.UserVerificationRequirementNotMet, Fido2ErrorMessages.UserVerificationRequirementNotMet);

        // 16. If the credential backup state is used as part of Relying Party business logic or policy, let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData.
        // Compare currentBe and currentBs with credentialRecord.BE and credentialRecord.BS and apply Relying Party policy, if any.
        if (authData.IsBackupEligible && config.BackupEligibleCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Disallowed ||
            !authData.IsBackupEligible && config.BackupEligibleCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Required)
            throw new Fido2VerificationException(Fido2ErrorCode.BackupEligibilityRequirementNotMet, Fido2ErrorMessages.BackupEligibilityRequirementNotMet);

        if (authData.IsBackedUp && config.BackedUpCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Disallowed ||
            !authData.IsBackedUp && config.BackedUpCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Required)
            throw new Fido2VerificationException(Fido2ErrorCode.BackupStateRequirementNotMet, Fido2ErrorMessages.BackupStateRequirementNotMet);

        // 17. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected,
        // considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions,
        // i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        byte[]? devicePublicKeyResult = null;
        if (Raw.Extensions?.DevicePubKey is not null)
        {
            devicePublicKeyResult = await DevicePublicKeyAuthenticationAsync(storedDevicePublicKeys, Raw.Extensions, AuthenticatorData, hash).ConfigureAwait(false);
        }

        // Pretty sure these conditions are not able to be met due to the AuthenticatorData constructor implementation        
        if (authData.HasExtensionsData && (authData.Extensions is null || authData.Extensions.Length is 0))
            throw new Fido2VerificationException(Fido2ErrorCode.MalformedExtensionsDetected, Fido2ErrorMessages.MalformedExtensionsDetected);

        if (!authData.HasExtensionsData && authData.Extensions != null)
            throw new Fido2VerificationException(Fido2ErrorCode.UnexpectedExtensionsDetected, Fido2ErrorMessages.UnexpectedExtensionsDetected);

        // 18. Let hash be the result of computing a hash over the cData using SHA-256.
        // done earlier in step 13

        // 19. Using credentialRecord.publicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
        byte[] data = DataHelper.Concat(Raw.Response.AuthenticatorData, hash);

        if (storedPublicKey is null || storedPublicKey.Length is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.MissingStoredPublicKey, Fido2ErrorMessages.MissingStoredPublicKey);

        var cpk = new CredentialPublicKey(storedPublicKey);

        if (!cpk.Verify(data, Signature))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignature, Fido2ErrorMessages.InvalidSignature);

        // 20. If authData.signCount is nonzero or credentialRecord.signCount is nonzero
        if (authData.SignCount > 0 && authData.SignCount <= storedSignatureCounter)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignCount, Fido2ErrorMessages.SignCountIsLessThanSignatureCounter);

        // 21. If response.attestationObject is present and the Relying Party wishes to verify the attestation then...
        if (AttestationObject is not null)
        {
            // ... perform CBOR decoding on attestationObject to obtain the attestation statement format fmt, and the attestation statement attStmt.
            var cborAttestation = (CborMap)CborObject.Decode(AttestationObject);
            string fmt = (string)cborAttestation["fmt"]!;
            var attStmt = (CborMap)cborAttestation["attStmt"]!;

            // 1. Verify that the AT bit in the flags field of authData is set, indicating that attested credential data is included.
            if (!authData.HasAttestedCredentialData)
                throw new Fido2VerificationException(Fido2ErrorCode.AttestedCredentialDataFlagNotSet, Fido2ErrorMessages.AttestedCredentialDataFlagNotSet);

            // 2. Verify that the credentialPublicKey and credentialId fields of the attested credential data in authData match credentialRecord.publicKey and credentialRecord.id, respectively.
            if (!Raw.Id.SequenceEqual(authData.AttestedCredentialData.CredentialId))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, "Stored credential id does not match id in attested credential data");

            if (!storedPublicKey.SequenceEqual(authData.AttestedCredentialData.CredentialPublicKey.GetBytes()))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, "Stored public key does not match public key in attested credential data");

            // 3. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
            var verifier = AttestationVerifier.Create(fmt);

            // 4. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
            (var attType, var trustPath) = await verifier.VerifyAsync(attStmt, AuthenticatorData, hash).ConfigureAwait(false);

            // 5. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys)
            //     for that attestation type and attestation statement format fmt, from a trusted source or from policy. 
            //     For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.

            MetadataBLOBPayloadEntry? metadataEntry = null;
            if (metadataService != null)
                metadataEntry = await metadataService.GetEntryAsync(authData.AttestedCredentialData.AaGuid, cancellationToken);

            // while conformance testing, we must reject any authenticator that we cannot get metadata for
            if (metadataService?.ConformanceTesting() is true && metadataEntry is null && attType != AttestationType.None && fmt is not "fido-u2f")
                throw new Fido2VerificationException(Fido2ErrorCode.AaGuidNotFound, "AAGUID not found in MDS test metadata");

            TrustAnchor.Verify(metadataEntry, trustPath);
        }

        return new VerifyAssertionResult
        {
            Status = "ok",
            CredentialId = Raw.Id,
            SignCount = authData.SignCount,
            IsBackedUp = authData.IsBackedUp,
            DevicePublicKey = devicePublicKeyResult,
        };
    }

    /// <summary>
    /// If the devicePubKey extension was included on a navigator.credentials.get() call, then the below 
    /// verification steps are performed in the context of this step of § 7.2 Verifying an Authentication Assertion using 
    /// these variables established therein: credential, clientExtensionResults, authData, and hash. Relying Party policy 
    /// may specify whether a response without a devicePubKey is acceptable.
    /// <see cref="https://w3c.github.io/webauthn/#sctn-device-publickey-extension-verification-get"/>
    /// <param name="clientExtensionResults"></param>
    /// <param name="authData"></param>
    /// <param name="hash"></param>
    /// </summary>
    private static async ValueTask<byte[]?> DevicePublicKeyAuthenticationAsync(
        List<byte[]> storedDevicePublicKeys,
        AuthenticationExtensionsClientOutputs clientExtensionResults,
        AuthenticatorData authData,
        byte[] hash)
    {
        // 1. Let attObjForDevicePublicKey be the value of the devicePubKey member of clientExtensionResults.
        var attObjForDevicePublicKey = clientExtensionResults.DevicePubKey!;

        // 2. Verify that attObjForDevicePublicKey is valid CBOR conforming to the syntax defined above and
        // perform CBOR decoding on it to extract the contained fields: aaguid, dpk, scope, nonce, fmt, attStmt.
        var devicePublicKeyAuthenticatorOutput = DevicePublicKeyAuthenticatorOutput.Parse(attObjForDevicePublicKey.AuthenticatorOutput);

        // 3. Verify that signature is a valid signature over the assertion signature input (i.e. authData and hash) by the device public key dpk. 
        if (!devicePublicKeyAuthenticatorOutput.DevicePublicKey.Verify(DataHelper.Concat(authData.ToByteArray(), hash), attObjForDevicePublicKey.Signature))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignature, Fido2ErrorMessages.InvalidSignature);

        // 4. If the Relying Party's user account mapped to the credential.id in play (i.e., for the user being
        // authenticated) holds aaguid, dpk and scope values corresponding to the extracted attObjForDevicePublicKey
        // fields, then perform binary equality checks between the corresponding stored values and the extracted field
        // values. The Relying Party MAY have more than one set of {aaguid, dpk, scope} values mapped to the user
        // account and credential.id pair and each set MUST be checked.
        if (storedDevicePublicKeys.Count > 0)
        {
            var matchedDpkRecords = new List<DevicePublicKeyAuthenticatorOutput>();

            foreach (var storedDevicePublicKey in storedDevicePublicKeys)
            {
                var dpkRecord = DevicePublicKeyAuthenticatorOutput.Parse(storedDevicePublicKey);
                if (dpkRecord.GetAuthenticationMatcher().SequenceEqual(devicePublicKeyAuthenticatorOutput.GetAuthenticationMatcher())
                    && dpkRecord.Scope.Equals(devicePublicKeyAuthenticatorOutput.Scope))
                {
                    matchedDpkRecords.Add(dpkRecord);
                }
            }

            // more than one match
            if (matchedDpkRecords.Count > 1)
            {
                // Some form of error has occurred. It is indeterminate whether this is a known device. Terminate these verification steps.
                throw new Fido2VerificationException(Fido2ErrorCode.DevicePublicKeyAuthentication, Fido2ErrorMessages.NonUniqueDevicePublicKey);
            }
            // exactly one match
            else if (matchedDpkRecords.Count is 1)
            {
                // This is likely a known device.
                // If fmt's value is "none" then there is no attestation signature to verify and this is a known device public key with a valid signature and thus a known device. Terminate these verification steps.
                if (devicePublicKeyAuthenticatorOutput.Fmt is "none")
                {
                    return null;
                }
                // Otherwise, check attObjForDevicePublicKey's attStmt by performing a binary equality check between the corresponding stored and extracted attStmt values.
                else if (devicePublicKeyAuthenticatorOutput.AttStmt.Encode().SequenceEqual(matchedDpkRecords.First().AttStmt.Encode()))
                {
                    // Note: This authenticator is not generating a fresh per-response random nonce.
                    return null;
                }
                else
                {
                    // Optionally, if attestation was requested and the RP wishes to verify it, verify that attStmt
                    // is a correct attestation statement, conveying a valid attestation signature, by using the
                    // attestation statement format fmt’s verification procedure given attStmt. See § 10.2.2.2.2
                    // Attestation calculations. Relying Party policy may specify which attestations are acceptable.
                    // https://www.w3.org/TR/webauthn/#defined-attestation-formats
                    var verifier = AttestationVerifier.Create(devicePublicKeyAuthenticatorOutput.Fmt);

                    // https://w3c.github.io/webauthn/#sctn-device-publickey-attestation-calculations
                    try
                    {
                        // This is a known device public key with a valid signature and valid attestation and thus a known device. Terminate these verification steps.
                        _ = await verifier.VerifyAsync(devicePublicKeyAuthenticatorOutput.AttStmt, devicePublicKeyAuthenticatorOutput.GetAuthenticatorData(), devicePublicKeyAuthenticatorOutput.GetHash()).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        // Some form of error has occurred. It is indeterminate whether this is a known device. Terminate these verification steps.
                        throw new Fido2VerificationException(Fido2ErrorCode.DevicePublicKeyAuthentication, Fido2ErrorMessages.InvalidDevicePublicKeyAttestation, ex);
                    }
                }
            }
            // This is possibly a new device public key signifying a new device.
            else if (matchedDpkRecords.Count == 0)
            {
                // Let matchedDpkKeys be a new empty set
                List<DevicePublicKeyAuthenticatorOutput> matchedDpkKeys = new();

                // For each dpkRecord in credentialRecord.devicePubKeys
                storedDevicePublicKeys.ForEach(storedDevicePublicKey =>
                {
                    var dpkRecord = DevicePublicKeyAuthenticatorOutput.Parse(storedDevicePublicKey);

                    // If dpkRecord.dpk equals dpk
                    if (dpkRecord.DevicePublicKey.GetBytes().SequenceEqual(devicePublicKeyAuthenticatorOutput.DevicePublicKey.GetBytes()))
                    {
                        // Append dpkRecord to matchedDpkKeys.
                        matchedDpkKeys.Add(dpkRecord);
                    }
                });

                // If matchedDpkKeys is empty
                if (matchedDpkKeys.Count == 0)
                {
                    // If fmt’s value is "none"
                    if (devicePublicKeyAuthenticatorOutput.Fmt.Equals("none"))
                        // There is no attestation signature to verify and this is a new device.
                        // Unless Relying Party policy specifies that this attestation is unacceptable, Create a new device-bound key record and then terminate these verification steps.
                        return devicePublicKeyAuthenticatorOutput.Encode();

                    // Otherwise
                    else
                    {
                        // Optionally, if attestation was requested and the RP wishes to verify it, verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt. See § 10.2.2.2.2 Attestation calculations.
                        // Relying Party policy may specify which attestations are acceptable.
                        var verifier = AttestationVerifier.Create(devicePublicKeyAuthenticatorOutput.Fmt);
                        // https://w3c.github.io/webauthn/#sctn-device-publickey-attestation-calculations
                        try
                        {
                            // This is a known device public key with a valid signature and valid attestation and thus a known device. Terminate these verification steps.
                            _ = await verifier.VerifyAsync(devicePublicKeyAuthenticatorOutput.AttStmt, devicePublicKeyAuthenticatorOutput.GetAuthenticatorData(), devicePublicKeyAuthenticatorOutput.GetHash()).ConfigureAwait(false);
                            return devicePublicKeyAuthenticatorOutput.Encode();
                        }
                        catch (Exception ex)
                        {
                            // Some form of error has occurred. It is indeterminate whether this is a known device. Terminate these verification steps.
                            throw new Fido2VerificationException(Fido2ErrorCode.DevicePublicKeyAuthentication, Fido2ErrorMessages.InvalidDevicePublicKeyAttestation, ex);
                        }
                    }
                }
                else
                {
                    // Otherwise there is some form of error: we received a known dpk value, but one or more of the
                    // accompanying aaguid, scope, or fmt values did not match what the Relying Party has stored
                    // along with that dpk value. Terminate these verification steps.
                    throw new Fido2VerificationException(Fido2ErrorCode.DevicePublicKeyAuthentication, Fido2ErrorMessages.MissingStoredPublicKey);
                }
            }
        }

        // Otherwise, the Relying Party does not have attObjForDevicePublicKey fields presently mapped to this user account and credential.id pair:
        else
        {
            // If fmt’s value is "none" there is no attestation signature to verify.
            // Complete the steps in § 7.2 Verifying an Authentication Assertion and, if those steps are successful, store the extracted aaguid, dpk, scope, fmt, attStmt values indexed to the credential.id in the user account.
            // Terminate these verification steps.
            if (devicePublicKeyAuthenticatorOutput.Fmt.Equals("none"))
                return devicePublicKeyAuthenticatorOutput.Encode();
            // Otherwise, verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt. See § 10.2.2.2.2 Attestation calculations.
            // Relying Party policy may specify which attestations are acceptable.
            else
            {
                var verifier = AttestationVerifier.Create(devicePublicKeyAuthenticatorOutput.Fmt);
                // https://w3c.github.io/webauthn/#sctn-device-publickey-attestation-calculations
                try
                {
                    // This is a known device public key with a valid signature and valid attestation and thus a known device. Terminate these verification steps.
                    _ = await verifier.VerifyAsync(devicePublicKeyAuthenticatorOutput.AttStmt, devicePublicKeyAuthenticatorOutput.GetAuthenticatorData(), devicePublicKeyAuthenticatorOutput.GetHash()).ConfigureAwait(false);
                    return devicePublicKeyAuthenticatorOutput.Encode();
                }
                catch
                {
                    // Some form of error has occurred. It is indeterminate whether this is a known device. Terminate these verification steps.
                    throw new Fido2VerificationException(Fido2ErrorCode.MissingStoredPublicKey, Fido2ErrorMessages.MissingStoredPublicKey);
                }
            }
        }

        return null;
    }
}
