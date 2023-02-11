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

#nullable disable

namespace Fido2NetLib;

/// <summary>
/// The AuthenticatorAssertionResponse interface represents an authenticator's response to a client’s request for generation of a new authentication assertion given the Relying Party's challenge and optional list of credentials it is aware of.
/// This response contains a cryptographic signature proving possession of the credential private key, and optionally evidence of user consent to a specific transaction.
/// </summary>
public sealed class AuthenticatorAssertionResponse : AuthenticatorResponse
{
    private AuthenticatorAssertionResponse(byte[] clientDataJson) : base(clientDataJson)
    {
    }

    public AuthenticatorAssertionRawResponse Raw { get; init; }

    public byte[] AuthenticatorData { get; init; }

    public byte[] Signature { get; init; }

#nullable enable
    public byte[]? UserHandle { get; init; }
    public byte[]? AttestationObject { get; init; }
#nullable disable

    public static AuthenticatorAssertionResponse Parse(AuthenticatorAssertionRawResponse rawResponse)
    {
        var response = new AuthenticatorAssertionResponse(rawResponse.Response.ClientDataJson)
        {
            Raw = rawResponse, // accessed in Verify()
            AuthenticatorData = rawResponse.Response.AuthenticatorData,
            Signature = rawResponse.Response.Signature,
            UserHandle = rawResponse.Response.UserHandle,
            AttestationObject = rawResponse.Response.AttestationObject
        };

        return response;
    }

    /// <summary>
    /// Implements alghoritm from https://www.w3.org/TR/webauthn/#verifying-assertion
    /// </summary>
    /// <param name="options">The assertionoptions that was sent to the client</param>
    /// <param name="fullyQualifiedExpectedOrigins">
    /// The expected fully qualified server origins, used to verify that the signature is sent to the expected server
    /// </param>
    /// <param name="storedPublicKey">The stored public key for this CredentialId</param>
    /// <param name="storedSignatureCounter">The stored counter value for this CredentialId</param>
    /// <param name="isUserHandleOwnerOfCredId">A function that returns <see langword="true"/> if user handle is owned by the credential ID</param>
    /// <param name="requestTokenBindingId"></param>
    /// <param name="cancellationToken"></param>
    public async Task<AssertionVerificationResult> VerifyAsync(
        AssertionOptions options,
        Fido2Configuration config,
        byte[] storedPublicKey,
        List<byte[]> storedDevicePublicKeys,
        uint storedSignatureCounter,
        IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredId,
        byte[] requestTokenBindingId,
        CancellationToken cancellationToken = default)
    {
        BaseVerify(config.FullyQualifiedOrigins, options.Challenge, requestTokenBindingId);

        if (Raw.Type != PublicKeyCredentialType.PublicKey)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, "AssertionResponse type must be public-key");

        if (Raw.Id is null)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, "Id is missing");

        if (Raw.RawId is null)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, "RawId is missing");

        // 1. If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        if (options.AllowCredentials != null && options.AllowCredentials.Any())
        {
            // might need to transform x.Id and raw.id as described in https://www.w3.org/TR/webauthn/#publickeycredential
            if (!options.AllowCredentials.Any(x => x.Id.SequenceEqual(Raw.Id)))
                throw new Fido2VerificationException("Invalid");
        }

        // 2. Identify the user being authenticated and verify that this user is the owner of the public key credential source credentialSource identified by credential.id
        if (UserHandle != null)
        {
            if (UserHandle.Length is 0)
                throw new Fido2VerificationException(Fido2ErrorMessages.UserHandleIsEmpty);

            if (await isUserHandleOwnerOfCredId(new IsUserHandleOwnerOfCredentialIdParams(Raw.Id, UserHandle), cancellationToken) is false)
            {
                throw new Fido2VerificationException("User is not owner of the public key identified by the credential id");
            }
        }

        // 3. Using credential’s id attribute(or the corresponding rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key.
        // Credential public key passed in via storePublicKey parameter

        // 4. Let cData, authData and sig denote the value of credential’s response's clientDataJSON, authenticatorData, and signature respectively.
        //var cData = Raw.Response.ClientDataJson;
        var authData = new AuthenticatorData(AuthenticatorData);
        //var sig = Raw.Response.Signature;

        // 5. Let JSONtext be the result of running UTF-8 decode on the value of cData.
        // var JSONtext = Encoding.UTF8.GetBytes(cData.ToString());

        // 7. Verify that the value of C.type is the string webauthn.get.
        if (Type is not "webauthn.get")
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, "AssertionResponse must be webauthn.get");

        // 8. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        // 9. Verify that the value of C.origin matches the Relying Party's origin.
        // done in base class

        // 10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the attestation was obtained.If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        // Validated in BaseVerify.
        // todo: Needs testing

        // 11. Verify that the rpIdHash in aData is the SHA - 256 hash of the RP ID expected by the Relying Party.

        // https://www.w3.org/TR/webauthn/#sctn-appid-extension
        // FIDO AppID Extension:
        // If true, the AppID was used and thus, when verifying an assertion, the Relying Party MUST expect the rpIdHash to be the hash of the AppID, not the RP ID.
        var rpid = Raw.Extensions?.AppID ?? false ? options.Extensions?.AppID : options.RpId;
        byte[] hashedRpId = SHA256.HashData(Encoding.UTF8.GetBytes(rpid ?? string.Empty));
        byte[] hashedClientDataJson = SHA256.HashData(Raw.Response.ClientDataJson);            

        if (!authData.RpIdHash.SequenceEqual(hashedRpId))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidRpidHash, Fido2ErrorMessages.InvalidRpidHash);

        byte[] devicePublicKeyResult = null;
        if (Raw.Extensions?.DevicePubKey is not null)
        {
            devicePublicKeyResult = DevicePublicKeyAuthentication(storedDevicePublicKeys, Raw.Extensions, AuthenticatorData, hashedClientDataJson);
        }

        // 12. Verify that the User Present bit of the flags in authData is set.
        // UNLESS...userVerification is set to preferred or discouraged?
        // See Server-ServerAuthenticatorAssertionResponse-Resp3 Test server processing authenticatorData
        // P-5 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "preferred", and check that server succeeds
        // P-8 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "discouraged", and check that server succeeds
        // if ((!authData.UserPresent) && (options.UserVerification != UserVerificationRequirement.Discouraged && options.UserVerification != UserVerificationRequirement.Preferred)) throw new Fido2VerificationException("User Present flag not set in authenticator data");

        // 13 If user verification is required for this assertion, verify that the User Verified bit of the flags in aData is set.
        // UNLESS...userPresent is true?
        // see ee Server-ServerAuthenticatorAssertionResponse-Resp3 Test server processing authenticatorData
        // P-8 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "discouraged", and check that server succeeds
        if (options.UserVerification is UserVerificationRequirement.Required && !authData.UserVerified) 
            throw new Fido2VerificationException(Fido2ErrorCode.UserVerificationRequirementNotMet, Fido2ErrorMessages.UserVerificationRequirementNotMet);

        // 16. If the credential backup state is used as part of Relying Party business logic or policy, let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData.
        // Compare currentBe and currentBs with credentialRecord.BE and credentialRecord.BS and apply Relying Party policy, if any.
        if (authData.IsBackupEligible && !config.AllowBackupEligibleCredential)
            throw new Fido2VerificationException(Fido2ErrorCode.BackupEligibilityRequirementNotMet, Fido2ErrorMessages.BackupEligibilityRequirementNotMet);

        if (authData.BackupState && !config.AllowBackedUpCredential)
            throw new Fido2VerificationException(Fido2ErrorCode.BackupStateRequirementNotMet, Fido2ErrorMessages.BackupStateRequirementNotMet);

        // 14. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the get() call.In particular, any extension identifier values in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        // todo: Verify this (and implement extensions on options)
        if (authData.HasExtensionsData && (authData.Extensions is null || authData.Extensions.Length is 0)) 
            throw new Fido2VerificationException(Fido2ErrorCode.MalformedExtensionsDetected, Fido2ErrorMessages.MalformedExtensionsDetected);

        if (!authData.HasExtensionsData && authData.Extensions != null) 
            throw new Fido2VerificationException(Fido2ErrorCode.UnexpectedExtensionsDetected, Fido2ErrorMessages.UnexpectedExtensionsDetected);

        // 15.
        // Done earlier, hashedClientDataJson

        // 16. Using the credential public key looked up in step 3, verify that sig is a valid signature over the binary concatenation of aData and hash.
        byte[] data = DataHelper.Concat(Raw.Response.AuthenticatorData, hashedClientDataJson);
     
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
            string fmt = (string)cborAttestation["fmt"];
            var attStmt = (CborMap)cborAttestation["attStmt"];

            // 1. Verify that the AT bit in the flags field of authData is set, indicating that attested credential data is included.
            if (!authData.HasAttestedCredentialData)
                throw new Fido2VerificationException(Fido2ErrorCode.AttestedCredentialDataFlagNotSet, Fido2ErrorMessages.AttestedCredentialDataFlagNotSet);

            // 2. Verify that the credentialPublicKey and credentialId fields of the attested credential data in authData match credentialRecord.publicKey and credentialRecord.id, respectively.
            if (!Raw.Id.SequenceEqual(authData.AttestedCredentialData.CredentialID))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, "Stored credential id does not match id in attested credential data");

            if (!storedPublicKey.SequenceEqual(authData.AttestedCredentialData.CredentialPublicKey.GetBytes()))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, "Stored public key does not match public key in attested credential data");

            // 3. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
            var verifier = AttestationVerifier.Create(fmt);

            // 4. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
            (var attType, var trustPath) = verifier.Verify(attStmt, AuthenticatorData, hashedClientDataJson);

            // 5. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format fmt, from a trusted source or from policy.
            // The aaguid in the attested credential data can be used to guide this lookup.
            // TODO: Why?  What do we do with this info?
        }

        return new AssertionVerificationResult
        {
            Status = "ok",
            ErrorMessage = string.Empty,
            CredentialId = Raw.Id,
            Counter = authData.SignCount,
            BS = authData.BackupState,
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
    private static byte[] DevicePublicKeyAuthentication(
        List<byte[]> storedDevicePublicKeys,
        AuthenticationExtensionsClientOutputs clientExtensionResults,
        byte[] authData,
        byte[] hash
        )
    {
        // 1. Let attObjForDevicePublicKey be the value of the devicePubKey member of clientExtensionResults.
        var attObjForDevicePublicKey = clientExtensionResults.DevicePubKey;

        // 2. Verify that attObjForDevicePublicKey is valid CBOR conforming to the syntax defined above and
        // perform CBOR decoding on it to extract the contained fields: aaguid, dpk, scope, nonce, fmt, attStmt.
        DevicePublicKeyAuthenticatorOutput devicePublicKeyAuthenticatorOutput = new(attObjForDevicePublicKey.AuthenticatorOutput);

        // 3. Verify that signature is a valid signature over the assertion signature input (i.e. authData and hash) by the device public key dpk. 
        if (!devicePublicKeyAuthenticatorOutput.DevicePublicKey.Verify(DataHelper.Concat(authData, hash), attObjForDevicePublicKey.Signature))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignature, Fido2ErrorMessages.InvalidSignature);

        // 4. If the Relying Party's user account mapped to the credential.id in play (i.e., for the user being
        // authenticated) holds aaguid, dpk and scope values corresponding to the extracted attObjForDevicePublicKey
        // fields, then perform binary equality checks between the corresponding stored values and the extracted field
        // values. The Relying Party MAY have more than one set of {aaguid, dpk, scope} values mapped to the user
        // account and credential.id pair and each set MUST be checked.
        if (storedDevicePublicKeys.Count > 0)
        {
            List<DevicePublicKeyAuthenticatorOutput> matchedDpkRecords = new();
            storedDevicePublicKeys.ForEach(storedDevicePublicKey =>
            {
                DevicePublicKeyAuthenticatorOutput dpkRecord = new(storedDevicePublicKey);
                if (dpkRecord.AuthenticationMatcher.SequenceEqual(devicePublicKeyAuthenticatorOutput.AuthenticationMatcher)
                    && dpkRecord.Scope.Equals(devicePublicKeyAuthenticatorOutput.Scope))
                {
                    matchedDpkRecords.Add(dpkRecord);
                }
            });

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
                if (devicePublicKeyAuthenticatorOutput.Fmt.Equals("none"))
                    return null;
                // Otherwise, check attObjForDevicePublicKey's attStmt by performing a binary equality check between the corresponding stored and extracted attStmt values.
                else if (devicePublicKeyAuthenticatorOutput.AttStmt.Encode().SequenceEqual(matchedDpkRecords.FirstOrDefault().AttStmt.Encode()))
                {
                    // Note: This authenticator is not generating a fresh per-response random nonce.
                    return null;
                }
                else
                {
                    // Optionally, if attestation was requested and the RP wishes to verify it, verify that attStmt
                    // is a correct attestation statement, conveying a valid attestation signature, by using the
                    // attestation statement format fmt’s verification procedure given attStmt. See § 10.2.2.2.2
                    // Attestation calculations. Relying Party policy may specifiy which attestations are acceptable.
                    // https://www.w3.org/TR/webauthn/#defined-attestation-formats
                    var verifier = AttestationVerifier.Create(devicePublicKeyAuthenticatorOutput.Fmt);

                    // https://w3c.github.io/webauthn/#sctn-device-publickey-attestation-calculations
                    try
                    {
                        // This is a known device public key with a valid signature and valid attestation and thus a known device. Terminate these verification steps.
                        _ = verifier.Verify(devicePublicKeyAuthenticatorOutput.AttStmt, devicePublicKeyAuthenticatorOutput.AuthData, devicePublicKeyAuthenticatorOutput.Hash);
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
                    DevicePublicKeyAuthenticatorOutput dpkRecord = new(storedDevicePublicKey);

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
                        return devicePublicKeyAuthenticatorOutput.GetBytes();

                    // Otherwise
                    else
                    {
                        // Optionally, if attestation was requested and the RP wishes to verify it, verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt. See § 10.2.2.2.2 Attestation calculations.
                        // Relying Party policy may specifiy which attestations are acceptable.
                        var verifier = AttestationVerifier.Create(devicePublicKeyAuthenticatorOutput.Fmt);
                        // https://w3c.github.io/webauthn/#sctn-device-publickey-attestation-calculations
                        try
                        {
                            // This is a known device public key with a valid signature and valid attestation and thus a known device. Terminate these verification steps.
                            _ = verifier.Verify(devicePublicKeyAuthenticatorOutput.AttStmt, devicePublicKeyAuthenticatorOutput.AuthData, devicePublicKeyAuthenticatorOutput.Hash);
                            return devicePublicKeyAuthenticatorOutput.GetBytes();
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
                    // Otherwise there is some form of error: we recieved a known dpk value, but one or more of the
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
                return devicePublicKeyAuthenticatorOutput.GetBytes();
            // Otherwise, verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt. See § 10.2.2.2.2 Attestation calculations.
            // Relying Party policy may specifiy which attestations are acceptable.
            else
            {
                var verifier = AttestationVerifier.Create(devicePublicKeyAuthenticatorOutput.Fmt);
                // https://w3c.github.io/webauthn/#sctn-device-publickey-attestation-calculations
                try
                {
                    // This is a known device public key with a valid signature and valid attestation and thus a known device. Terminate these verification steps.
                    _ = verifier.Verify(devicePublicKeyAuthenticatorOutput.AttStmt, devicePublicKeyAuthenticatorOutput.AuthData, devicePublicKeyAuthenticatorOutput.Hash);
                    return devicePublicKeyAuthenticatorOutput.GetBytes();
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
