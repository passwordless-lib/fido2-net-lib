using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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

    public static AuthenticatorAssertionResponse Parse(AuthenticatorAssertionRawResponse rawResponse)
    {
        return new AuthenticatorAssertionResponse(
            raw: rawResponse,
            authenticatorData: AuthenticatorData.Parse(rawResponse.Response.AuthenticatorData)
        );
    }

    /// <summary>
    /// Implements algorithm from https://www.w3.org/TR/webauthn/#verifying-assertion.
    /// </summary>
    /// <param name="options">The original assertion options that was sent to the client.</param>
    /// <param name="config"></param>
    /// <param name="storedPublicKey">The stored public key for this CredentialId.</param>
    /// <param name="storedSignatureCounter">The stored counter value for this CredentialId</param>
    /// <param name="isUserHandleOwnerOfCredId">A function that returns <see langword="true"/> if user handle is owned by the credential ID.</param>
    /// <param name="metadataService"></param>
    /// <param name="requestTokenBindingId">DO NOT USE - Deprecated, but kept in code due to conformance testing tool</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    public async Task<VerifyAssertionResult> VerifyAsync(
        AssertionOptions options,
        Fido2Configuration config,
        byte[] storedPublicKey,
        uint storedSignatureCounter,
        IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredId,
        IMetadataService? metadataService,
        byte[]? requestTokenBindingId,
        CancellationToken cancellationToken = default)
    {
        BaseVerify(config.FullyQualifiedOrigins, options.Challenge, requestTokenBindingId);

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

        var rpid = Raw.ClientExtensionResults?.AppID ?? false ? options.Extensions?.AppID : options.RpId;

        byte[] hashedRpId = SHA256.HashData(Encoding.UTF8.GetBytes(rpid ?? string.Empty));
        byte[] hash = SHA256.HashData(Raw.Response.ClientDataJson);

        if (!authData.RpIdHash.SequenceEqual(hashedRpId))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidRpidHash, Fido2ErrorMessages.InvalidRpidHash);

        var conformanceTesting = metadataService != null && metadataService.ConformanceTesting();

        // 14. Verify that the UP bit of the flags in authData is set.
        // Todo: Conformance testing verifies the UVP flags differently than W3C spec, simplify this by removing the mention of conformanceTesting when conformance tools are updated)
        if (!authData.UserPresent && !conformanceTesting)
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



        // Pretty sure these conditions are not able to be met due to the AuthenticatorData constructor implementation
        if (authData.HasExtensionsData && (authData.Extensions is null || authData.Extensions.Length is 0))
            throw new Fido2VerificationException(Fido2ErrorCode.MalformedExtensionsDetected, Fido2ErrorMessages.MalformedExtensionsDetected);

        if (!authData.HasExtensionsData && authData.Extensions != null)
            throw new Fido2VerificationException(Fido2ErrorCode.UnexpectedExtensionsDetected, Fido2ErrorMessages.UnexpectedExtensionsDetected);

        // 18. Let hash be the result of computing a hash over the cData using SHA-256.
        // done earlier in step 13

        // 19. Using credentialRecord.publicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
        byte[] data = [.. Raw.Response.AuthenticatorData, .. hash];

        if (storedPublicKey is null || storedPublicKey.Length is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.MissingStoredPublicKey, Fido2ErrorMessages.MissingStoredPublicKey);

        var cpk = new CredentialPublicKey(storedPublicKey);

        if (!cpk.Verify(data, Signature))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignature, Fido2ErrorMessages.InvalidSignature);

        // 20. If authData.signCount is nonzero or credentialRecord.signCount is nonzero
        if (authData.SignCount > 0 && authData.SignCount <= storedSignatureCounter)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignCount, Fido2ErrorMessages.SignCountIsLessThanSignatureCounter);


        return new VerifyAssertionResult
        {
            CredentialId = Raw.Id,
            SignCount = authData.SignCount,
            IsBackedUp = authData.IsBackedUp

        };
    }
}
