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


        // 17. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected,
        // considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions,
        // i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.

        // Pretty sure these conditions are not able to be met due to the AuthenticatorData constructor implementation
        if (authData.HasExtensionsData && (authData.Extensions is null || authData.Extensions.Length is 0))
            throw new Fido2VerificationException(Fido2ErrorCode.MalformedExtensionsDetected, Fido2ErrorMessages.MalformedExtensionsDetected);

        if (!authData.HasExtensionsData && authData.Extensions != null)
            throw new Fido2VerificationException(Fido2ErrorCode.UnexpectedExtensionsDetected, Fido2ErrorMessages.UnexpectedExtensionsDetected);

        // Validate extension inputs and outputs for assertion ceremony
        ValidateAssertionExtensionInputs(options.Extensions);
        ValidateAssertionExtensionOutputs(options.Extensions, Raw.ClientExtensionResults);

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
            CredentialId = Raw.RawId,
            SignCount = authData.SignCount,
            IsBackedUp = authData.IsBackedUp

        };
    }

    /// <summary>
    /// Validates extension inputs during assertion ceremony.
    /// Ensures that extension input parameters are well-formed and don't violate constraints.
    /// </summary>
    private static void ValidateAssertionExtensionInputs(AuthenticationExtensionsClientInputs? extensions)
    {
        if (extensions == null)
            return;

        // Validate PRF input structure
        if (extensions.PRF != null)
        {
            ValidatePRFInput(extensions.PRF);
        }

        // Validate LargeBlob input constraints for assertion
        if (extensions.LargeBlob != null)
        {
            ValidateLargeBlobAssertionInput(extensions.LargeBlob);
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
    /// Validates PRF extension input structure.
    /// Ensures eval inputs have proper format and constraints.
    /// </summary>
    private static void ValidatePRFInput(AuthenticationExtensionsPRFInputs prfInput)
    {
        // PRF input must have eval or evalByCredential (or both)
        if (prfInput.Eval == null && prfInput.EvalByCredential == null)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "PRF extension input must have 'eval' or 'evalByCredential'");
        }

        // Validate eval if present
        if (prfInput.Eval != null)
        {
            ValidatePRFInputValues(prfInput.Eval, "eval");
        }

        // Validate evalByCredential if present
        if (prfInput.EvalByCredential.HasValue)
        {
            var evalByCred = prfInput.EvalByCredential.Value;
            // Credential ID should be non-empty
            if (string.IsNullOrEmpty(evalByCred.Key))
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    "PRF extension 'evalByCredential' has empty credential ID");
            }
            // Credential values should be valid
            ValidatePRFInputValues(evalByCred.Value, "evalByCredential");
        }
    }

    /// <summary>
    /// Validates PRF input values (first and optional second salts).
    /// </summary>
    private static void ValidatePRFInputValues(AuthenticationExtensionsPRFValues values, string fieldName)
    {
        // First value is required
        if (values.First == null || values.First.Length == 0)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                $"PRF extension '{fieldName}' has missing or empty 'first' value");
        }

        // PRF inputs are typically 32 bytes but allow flexibility
        if (values.First.Length < 16 || values.First.Length > 512)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                $"PRF extension '{fieldName}' 'first' value has unexpected length: {values.First.Length}. Expected 16-512 bytes.");
        }

        // Second value is optional, but if present should have reasonable length
        if (values.Second != null && values.Second.Length > 0)
        {
            if (values.Second.Length < 16 || values.Second.Length > 512)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"PRF extension '{fieldName}' 'second' value has unexpected length: {values.Second.Length}. Expected 16-512 bytes.");
            }
        }
    }

    /// <summary>
    /// Validates LargeBlob extension input during assertion.
    /// Ensures read and write constraints are met.
    /// </summary>
    private static void ValidateLargeBlobAssertionInput(AuthenticationExtensionsLargeBlobInputs blobInput)
    {
        bool hasRead = blobInput.Read;
        bool hasWrite = blobInput.Write != null && blobInput.Write.Length > 0;

        // Cannot request both read and write in the same operation
        if (hasRead && hasWrite)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "LargeBlob extension input cannot have both 'read' and 'write' set simultaneously");
        }

        // At least one of read or write should be requested
        if (!hasRead && !hasWrite)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "LargeBlob extension input must have either 'read' or 'write' set");
        }

        // If write is requested, validate blob size
        if (hasWrite)
        {
            if (blobInput.Write!.Length == 0)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    "LargeBlob extension 'write' field is empty");
            }

            // Most authenticators support 512-2048 bytes, but spec allows larger
            // Enforce a reasonable limit to prevent abuse
            if (blobInput.Write.Length > 65536) // 64KB limit
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"LargeBlob extension 'write' blob size ({blobInput.Write.Length}) exceeds maximum limit of 64KB");
            }
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
            ValidatePRFOutput(clientExtensionResults.PRF);
        }

        // Validate extensions discovery (exts) output
        if (requestedExtensions.Extensions.HasValue && clientExtensionResults.Extensions != null)
        {
            ValidateExtensionsDiscoveryOutput(clientExtensionResults.Extensions);
        }

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
    /// Validates extensions discovery (exts) output.
    /// </summary>
    private static void ValidateExtensionsDiscoveryOutput(string[] supportedExtensions)
    {
        if (supportedExtensions == null)
            return;

        foreach (var ext in supportedExtensions)
        {
            if (string.IsNullOrWhiteSpace(ext))
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    "Extension identifier in discovery output is empty or whitespace");
            }

            if (ext.Length > 128)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"Extension identifier '{ext}' is excessively long");
            }
        }
    }

    /// <summary>
    /// Validates PRF extension output format per WebAuthn L3 Section 9.
    /// https://w3c.github.io/webauthn/#prf-extension
    /// </summary>
    private static void ValidatePRFOutput(AuthenticationExtensionsPRFOutputs prfOutput)
    {
        // If enabled is false, results must not be present
        if (!prfOutput.Enabled && prfOutput.Results != null)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "PRF extension output has enabled=false but results are present");
        }

        // If enabled is true and results are present, validate the results format
        if (prfOutput.Enabled && prfOutput.Results != null)
        {
            ValidatePRFValues(prfOutput.Results);
        }
    }

    /// <summary>
    /// Validates PRF values (first and second salts).
    /// Both first and second should be byte arrays of appropriate length.
    /// </summary>
    private static void ValidatePRFValues(AuthenticationExtensionsPRFValues values)
    {
        // First value is required
        if (values.First == null || values.First.Length == 0)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "PRF extension output has missing or empty 'first' value");
        }

        // PRF output should be 32 bytes (SHA-256 output) or 64 bytes
        // Allow flexibility for different PRF implementations
        if (values.First.Length != 32 && values.First.Length != 64)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                $"PRF extension 'first' value has unexpected length: {values.First.Length}. Expected 32 or 64 bytes.");
        }

        // Second value is optional, but if present should have same length as first
        if (values.Second != null && values.Second.Length > 0)
        {
            if (values.Second.Length != values.First.Length)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"PRF extension 'second' value length ({values.Second.Length}) does not match 'first' value length ({values.First.Length})");
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
        bool requestedWrite = blobInput.Write != null && blobInput.Write.Length > 0;

        // Cannot request both read and write in the same operation
        if (requestedRead && requestedWrite)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "LargeBlob extension input cannot have both 'read' and 'write' set");
        }

        // If read was requested, blob should be present (or null if read returned nothing)
        // If blob is present, it should be properly formatted
        if (requestedRead && blobOutput.Blob != null && blobOutput.Blob.Length > 0)
        {
            // Blob should not exceed authenticator's large blob storage limit
            // Most authenticators support 512 bytes, but spec allows up to 512 bytes
            // We don't strictly validate the size here as it's implementation-specific
            if (blobOutput.Blob.Length > 65536) // Reasonable upper limit
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"LargeBlob extension blob size ({blobOutput.Blob.Length}) exceeds reasonable limit");
            }
        }

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
