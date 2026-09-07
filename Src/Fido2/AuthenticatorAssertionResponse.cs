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
    /// <param name="storedBackupEligible">
    /// The value of the BE flag recorded when this credential was registered, or <see langword="null"/> if the
    /// Relying Party does not track backup eligibility. Backup eligibility is a permanent property of a credential,
    /// so when a value is supplied it MUST match the BE flag of this assertion.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    public async Task<VerifyAssertionResult> VerifyAsync(
        AssertionOptions options,
        Fido2Configuration config,
        byte[] storedPublicKey,
        uint storedSignatureCounter,
        IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredId,
        IMetadataService? metadataService,
        byte[]? requestTokenBindingId,
        bool? storedBackupEligible = null,
        CancellationToken cancellationToken = default)
    {
        BaseVerify(config.FullyQualifiedOrigins, options.Challenge, requestTokenBindingId, config.AllowCrossOriginRequests);

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
            if (!options.AllowCredentials.Any(x => x.Id.SequenceEqual(Raw.RawId)))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, Fido2ErrorMessages.CredentialIdNotInAllowedCredentials);
        }

        // 6. Identify the user being authenticated and verify that this user is the owner of the public key credential source credentialSource identified by credential.id
        if (UserHandle != null)
        {
            if (UserHandle.Length is 0)
                throw new Fido2VerificationException(Fido2ErrorMessages.UserHandleIsEmpty);

            if (await isUserHandleOwnerOfCredId(new IsUserHandleOwnerOfCredentialIdParams(Raw.RawId, UserHandle), cancellationToken) is false)
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

        // 15. Verify that the rpIdHash in aData is the SHA - 256 hash of the RP ID expected by the Relying Party.

        // https://www.w3.org/TR/webauthn/#sctn-appid-extension
        // FIDO AppID Extension:
        // If true, the AppID was used and thus, when verifying an assertion, the Relying Party MUST expect the rpIdHash to be the hash of the AppID, not the RP ID.

        var rpid = Raw.ClientExtensionResults?.AppID ?? false ? options.Extensions?.AppID : options.RpId;

        byte[] hashedRpId = SHA256.HashData(Encoding.UTF8.GetBytes(rpid ?? string.Empty));
        byte[] hash = SHA256.HashData(Raw.Response.ClientDataJson);

        if (!authData.RpIdHash.SequenceEqual(hashedRpId))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidRpidHash, Fido2ErrorMessages.InvalidRpidHash);

        var conformanceTesting = metadataService != null && metadataService.ConformanceTesting();

        // 16. Verify that the UP bit of the flags in authData is set.
        // Todo: Conformance testing verifies the UVP flags differently than W3C spec, simplify this by removing the mention of conformanceTesting when conformance tools are updated)
        if (!authData.UserPresent && !conformanceTesting)
            throw new Fido2VerificationException(Fido2ErrorCode.UserPresentFlagNotSet, Fido2ErrorMessages.UserPresentFlagNotSet);

        // 17. If the Relying Party requires user verification for this assertion, verify that the UV bit of the flags in authData is set.
        if (options.UserVerification is UserVerificationRequirement.Required && !authData.UserVerified)
            throw new Fido2VerificationException(Fido2ErrorCode.UserVerificationRequirementNotMet, Fido2ErrorMessages.UserVerificationRequirementNotMet);

        // 18. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
        //     A credential that is not backup eligible can never be backed up, so this combination is
        //     malformed regardless of Relying Party policy.
        if (!authData.IsBackupEligible && authData.IsBackedUp)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidBackupFlags, Fido2ErrorMessages.InvalidBackupFlags);

        // 19. If the credential backup state is used as part of Relying Party business logic or policy, let currentBe and currentBs
        //     be the values of the BE and BS bits, respectively, of the flags in authData. Compare currentBe and currentBs with
        //     credentialRecord.backupEligible and credentialRecord.backupState and apply Relying Party policy, if any.
        //
        //     Backup eligibility is fixed for the lifetime of a credential, so a change of BE relative to the value recorded at
        //     registration is not a policy question -- it means this is not the credential that was registered.
        if (storedBackupEligible is bool recordedBackupEligible && recordedBackupEligible != authData.IsBackupEligible)
            throw new Fido2VerificationException(Fido2ErrorCode.BackupEligibilityChanged, Fido2ErrorMessages.BackupEligibilityChanged);

        if (authData.IsBackupEligible && config.BackupEligibleCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Disallowed ||
            !authData.IsBackupEligible && config.BackupEligibleCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Required)
            throw new Fido2VerificationException(Fido2ErrorCode.BackupEligibilityRequirementNotMet, Fido2ErrorMessages.BackupEligibilityRequirementNotMet);

        if (authData.IsBackedUp && config.BackedUpCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Disallowed ||
            !authData.IsBackedUp && config.BackedUpCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Required)
            throw new Fido2VerificationException(Fido2ErrorCode.BackupStateRequirementNotMet, Fido2ErrorMessages.BackupStateRequirementNotMet);


        // 23. (Out of order: the spec processes extension outputs near the end of the ceremony, but nothing
        //     in between depends on them, and validating early fails a bad response before the signature check.)
        //     Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected,
        // considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions,
        // i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.

        // Pretty sure these conditions are not able to be met due to the AuthenticatorData constructor implementation
        if (authData.HasExtensionsData && (authData.Extensions is null || authData.Extensions.Length is 0))
            throw new Fido2VerificationException(Fido2ErrorCode.MalformedExtensionsDetected, Fido2ErrorMessages.MalformedExtensionsDetected);

        if (!authData.HasExtensionsData && authData.Extensions != null)
            throw new Fido2VerificationException(Fido2ErrorCode.UnexpectedExtensionsDetected, Fido2ErrorMessages.UnexpectedExtensionsDetected);

        // Validate extension inputs and outputs for assertion ceremony
        ValidateAssertionExtensionInputs(options.Extensions, options.AllowCredentials);
        ValidateAssertionExtensionOutputs(options.Extensions, Raw.ClientExtensionResults);

        // 20. Let hash be the result of computing a hash over the cData using SHA-256.
        // done earlier in step 15

        // 21. Using credentialRecord.publicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
        byte[] data = [.. Raw.Response.AuthenticatorData, .. hash];

        if (storedPublicKey is null || storedPublicKey.Length is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.MissingStoredPublicKey, Fido2ErrorMessages.MissingStoredPublicKey);

        var cpk = new CredentialPublicKey(storedPublicKey);

        if (!cpk.Verify(data, Signature))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignature, Fido2ErrorMessages.InvalidSignature);

        // 22. If authData.signCount is nonzero or credentialRecord.signCount is nonzero
        if (authData.SignCount > 0 && authData.SignCount <= storedSignatureCounter)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignCount, Fido2ErrorMessages.SignCountIsLessThanSignatureCounter);


        return new VerifyAssertionResult
        {
            CredentialId = Raw.RawId,
            SignCount = authData.SignCount,
            IsBackedUp = authData.IsBackedUp,
            IsUserVerified = authData.UserVerified,
            AuthenticatorExtensionResults = authData.Extensions?.Outputs ?? new AuthenticationExtensionsAuthenticatorOutputs()
        };
    }

    /// <summary>
    /// Validates extension inputs during assertion ceremony.
    /// Ensures that extension input parameters are well-formed and don't violate constraints.
    /// </summary>
    private static void ValidateAssertionExtensionInputs(
        AuthenticationExtensionsClientInputs? extensions,
        IReadOnlyList<PublicKeyCredentialDescriptor>? allowCredentials)
    {
        if (extensions == null)
            return;

        // Validate PRF input structure
        if (extensions.PRF != null)
        {
            ClientExtensionValidation.ValidateAssertionPRFInput(extensions.PRF, allowCredentials);
        }

        // Validate LargeBlob input constraints for assertion
        if (extensions.LargeBlob != null)
        {
            ValidateLargeBlobAssertionInput(extensions.LargeBlob, allowCredentials);
        }

        // credBlob stores a blob with a new credential, and pinComplexityPolicy reports the policy in force
        // when one is created; both are registration-only. Reading a stored blob back is getCredBlob.
        if (extensions.CredBlob != null)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "The credBlob extension is not valid during assertion. Use getCredBlob to read the blob back.");
        }

        if (extensions.PinComplexityPolicy.HasValue)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "The pinComplexityPolicy extension is not valid during assertion. Use only during registration.");
        }

        // Validate credentialProtectionPolicy input
        if (extensions.CredentialProtectionPolicy.HasValue)
        {
            var policy = extensions.CredentialProtectionPolicy.Value;
            if (!Enum.IsDefined(typeof(CredentialProtectionPolicy), policy))
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"Invalid credentialProtectionPolicy value: {policy}");
            }
        }
    }

    /// <summary>
    /// Validates the <c>largeBlob</c> extension input of an authentication ceremony against the
    /// <paramref name="allowCredentials"/> it accompanies.
    /// </summary>
    /// <remarks>
    /// The three conditions a client rejects with a <c>NotSupportedError</c>, checked here so that they
    /// surface as diagnosable server-side failures. Requesting neither a read nor a write is not among them,
    /// and neither the blob nor the ceremony has a size limit that this specification states.
    /// <para>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension"/>
    /// </para>
    /// </remarks>
    private static void ValidateLargeBlobAssertionInput(
        AuthenticationExtensionsLargeBlobInputs blobInput,
        IReadOnlyList<PublicKeyCredentialDescriptor>? allowCredentials)
    {
        // "If support is present: return a DOMException whose name is NotSupportedError."
        if (blobInput.Support is not null)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "The largeBlob extension's 'support' is not valid during assertion. Use only during registration.");
        }

        bool hasWrite = blobInput.Write is not null;

        // "If both read and write are present: return a DOMException whose name is NotSupportedError."
        if (blobInput.Read && hasWrite)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "The largeBlob extension input cannot carry both 'read' and 'write'.");
        }

        // "If write is present: if allowCredentials does not contain exactly one element, return a
        //  DOMException whose name is NotSupportedError." The blob is stored against the credential that
        //  the assertion used, so the ceremony has to name exactly which one that will be.
        if (hasWrite && allowCredentials is not { Count: 1 })
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                $"The largeBlob extension's 'write' requires allowCredentials to contain exactly one credential, but it contains {allowCredentials?.Count ?? 0}.");
        }
    }

    /// <summary>
    /// Validates the format and content of extension outputs during assertion ceremony.
    /// Per WebAuthn L3 Section 7.2 Step 17, extension outputs must be as expected.
    /// </summary>
    private static void ValidateAssertionExtensionOutputs(
        AuthenticationExtensionsClientInputs? requestedExtensions,
        AuthenticationExtensionsClientOutputs? clientExtensionResults)
    {
        // If no extensions were requested, skip validation
        if (requestedExtensions == null || clientExtensionResults == null)
            return;

        // Validate PRF extension output (can be used in both registration and assertion)
        if (requestedExtensions.PRF != null && clientExtensionResults.PRF != null)
        {
            ClientExtensionValidation.ValidateAssertionPRFOutput(clientExtensionResults.PRF);
        }

        // Validate extensions discovery (exts) output
#pragma warning disable CS0618 // uvm and exts were removed in L3; still honoured for Level 2 callers
        if (requestedExtensions.Extensions.HasValue && clientExtensionResults.Extensions != null)
        {
            ClientExtensionValidation.ValidateExtensionsDiscoveryOutput(clientExtensionResults.Extensions);
        }
#pragma warning restore CS0618

        // Validate LargeBlob extension output (assertion context: read/write operations)
        if (requestedExtensions.LargeBlob != null && clientExtensionResults.LargeBlob != null)
        {
            ValidateLargeBlobAssertionOutput(requestedExtensions.LargeBlob, clientExtensionResults.LargeBlob);
        }

        // Validate credential protection policy output if requested
        if (requestedExtensions.CredentialProtectionPolicy.HasValue && clientExtensionResults.CredProtect.HasValue)
        {
            var credProtect = clientExtensionResults.CredProtect.Value;
            if (!Enum.IsDefined(typeof(CredentialProtectionPolicy), credProtect))
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"Invalid credentialProtectionPolicy value returned: {credProtect}");
            }
        }
    }

    /// <summary>
    /// Validates LargeBlob extension output during assertion (authentication ceremony).
    /// Per WebAuthn L3 Section 9, during assertion the output can contain:
    /// - 'blob' field if 'read' was requested
    /// - 'written' flag if 'write' was requested
    /// Cannot have both blob and written in the same response.
    /// https://w3c.github.io/webauthn/#sctn-large-blob-extension
    /// </summary>
    private static void ValidateLargeBlobAssertionOutput(
        AuthenticationExtensionsLargeBlobInputs blobInput,
        AuthenticationExtensionsLargeBlobOutputs blobOutput)
    {
        // During assertion, 'supported' field should not be present
        if (blobOutput.Supported)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "LargeBlob extension output contains 'supported' field during assertion. This field is only valid during registration.");
        }

        bool requestedRead = blobInput.Read;
        bool requestedWrite = blobInput.Write is not null;

        // Note: if write was requested but blobOutput.Written is false, the authenticator may have
        // had a legitimate reason to reject the write. We don't throw here; the RP can inspect
        // blobOutput.Written itself and decide whether that's acceptable.

        // If neither read nor write was requested, neither blob nor written should be present
        if (!requestedRead && !requestedWrite)
        {
            if ((blobOutput.Blob != null && blobOutput.Blob.Length > 0) || blobOutput.Written)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    "LargeBlob extension output contains data but neither read nor write was requested");
            }
        }
    }
}
