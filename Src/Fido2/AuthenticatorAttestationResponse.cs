using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

        // 13. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure
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
        byte[]? requestTokenBindingId,
        CredentialMediationRequirement mediation = CredentialMediationRequirement.Optional,
        CancellationToken cancellationToken = default)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
        // 5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        // 6. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
        //    Note: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.
        //    Above handled in base class constructor

        // 7. Verify that the value of C.type is webauthn.create
        if (Type is not "webauthn.create")
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestationResponse, Fido2ErrorMessages.AttestationResponseTypeNotWebAuthnGet);

        // 8. Verify that the value of C.challenge equals the base64url encoding of pkOptions.challenge.
        // 9. Verify that the value of C.origin is an origin expected by the Relying Party.
        // 10. If C.crossOrigin is present and set to true, verify that the Relying Party expects that this credential
        //     would have been created within an iframe that is not same-origin with its ancestors.
        // 11. If C.topOrigin is present, verify the same, and that it matches the origin of a page the Relying Party
        //     expects to be sub-framed within.
        // Validated in BaseVerify.
        // Token Binding is no longer part of the ceremony in Level 3; C.tokenBinding is still validated here for
        // callers on older clients.
        BaseVerify(config.FullyQualifiedOrigins, originalOptions.Challenge, requestTokenBindingId, config.AllowCrossOriginRequests);

        if (Raw.Id is null || Raw.Id.Length == 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestationResponse, Fido2ErrorMessages.AttestationResponseIdMissing);

        // credential.id is base64url(credential.rawId); a value that doesn't decode to exactly RawId's bytes is
        // either malformed or was tampered with in transit.
        byte[] decodedId;
        try
        {
            decodedId = Base64Url.DecodeFromChars(Raw.Id);
        }
        catch (FormatException e)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestationResponse, Fido2ErrorMessages.AttestationResponseIdNotBase64Url, e);
        }

        if (!decodedId.AsSpan().SequenceEqual(Raw.RawId))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestationResponse, Fido2ErrorMessages.AttestationResponseIdNotBase64Url);

        if (Raw.Type != PublicKeyCredentialType.PublicKey)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestationResponse, Fido2ErrorMessages.AttestationResponseNotPublicKey);

        var authData = AttestationObject.AuthData;

        // 12. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
        byte[] clientDataHash = SHA256.HashData(Raw.Response.ClientDataJson);
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(originalOptions.Rp.Id));

        // 13. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt,
        //    the authenticator data authData, and the attestation statement attStmt.
        //    Handled in AuthenticatorAttestationResponse::Parse()

        // 14. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party
        if (!authData.RpIdHash.AsSpan().SequenceEqual(rpIdHash))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidRpidHash, Fido2ErrorMessages.InvalidRpidHash);

        // 15. If options.mediation is not set to conditional, verify that the UP bit of the flags in authData is set.
        //     A conditional create surfaces alongside an existing sign-in rather than as its own prompt, so it
        //     may legitimately complete without a separate user presence test.
        if (mediation is not CredentialMediationRequirement.Conditional && !authData.UserPresent)
            throw new Fido2VerificationException(Fido2ErrorCode.UserPresentFlagNotSet, Fido2ErrorMessages.UserPresentFlagNotSet);

        // 16. If the Relying Party requires user verification for this registration, verify that the User Verified bit of the flags in authData is set.
        if (originalOptions.AuthenticatorSelection?.UserVerification is UserVerificationRequirement.Required && !authData.UserVerified)
            throw new Fido2VerificationException(Fido2ErrorCode.UserVerificationRequirementNotMet, Fido2ErrorMessages.UserVerificationRequirementNotMet);

        // 17. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
        //     A credential that is not backup eligible can never be backed up, so this combination is
        //     malformed regardless of Relying Party policy.
        if (!authData.IsBackupEligible && authData.IsBackedUp)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidBackupFlags, Fido2ErrorMessages.InvalidBackupFlags);

        // 18. If the Relying Party uses the credential's backup eligibility to inform its user experience flows and/or policies, evaluate the BE bit of the flags in authData.
        if (authData.IsBackupEligible && config.BackupEligibleCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Disallowed ||
            !authData.IsBackupEligible && config.BackupEligibleCredentialPolicy is Fido2Configuration.CredentialBackupPolicy.Required)
            throw new Fido2VerificationException(Fido2ErrorCode.BackupEligibilityRequirementNotMet, Fido2ErrorMessages.BackupEligibilityRequirementNotMet);

        if (!authData.HasAttestedCredentialData)
            throw new Fido2VerificationException(Fido2ErrorCode.AttestedCredentialDataFlagNotSet, Fido2ErrorMessages.AttestedCredentialDataFlagNotSet);

        // 20. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
        if (!originalOptions.PubKeyCredParams.Any(a => authData.AttestedCredentialData.CredentialPublicKey.IsSameAlg(a.Alg)))
            throw new Fido2VerificationException(Fido2ErrorCode.CredentialAlgorithmRequirementNotMet, Fido2ErrorMessages.CredentialAlgorithmRequirementNotMet);

        // 28. (Out of order: the spec processes extension outputs near the end of the ceremony, but nothing
        //     in between depends on them, and validating early fails a bad response before the expensive
        //     attestation work.)
        //     Process the client extension outputs in clientExtensionResults and the authenticator extension
        //     outputs in the extensions in authData as required by the Relying Party. Level 3 dropped Level 2's
        //     rule that no unrequested extension may appear -- "clients MAY set additional authenticator
        //     extensions or client extensions ... The Relying Party MUST be prepared to handle such situations"
        //     -- so unsolicited outputs are ignored unless config.UnsolicitedExtensionPolicy says otherwise.
        ValidateRegistrationExtensionInputs(originalOptions.Extensions);
        ValidateExtensions(originalOptions.Extensions, Raw.ClientExtensionResults, authData.Extensions, config.UnsolicitedExtensionPolicy);

        // 21. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt
        //     against the set of supported WebAuthn Attestation Statement Format Identifier values.
        // 22. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature,
        //     by using the attestation statement format fmt’s verification procedure given attStmt, authData
        //     and the hash of the serialized client data computed in step 12
        VerifyAttestationResult attestationResult;

        if (AttestationObject.Fmt is Compound.FormatIdentifier)
        {
            if (AttestationObject.AttStmt is not CborArray compoundAttStmt)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidCompoundAttestationStatement);

            attestationResult = await Compound.VerifyAsync(compoundAttStmt, AttestationObject.AuthData, clientDataHash, config.CompoundAttestationPolicy).ConfigureAwait(false);
        }
        else
        {
            if (AttestationObject.AttStmt is not CborMap attStmt)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidAttestationStatement);

            var verifier = AttestationVerifier.Create(AttestationObject.Fmt);

            attestationResult = await verifier.VerifyAsync(attStmt, AttestationObject.AuthData, clientDataHash).ConfigureAwait(false);
        }

        var (attType, trustPath) = attestationResult;

        // WebAuthn L3 §8.2.2: id-fido-gen-ce-sernum "MUST NOT be present in non-enterprise attestations".
        // The extension uniquely identifies one device, so accepting it outside an enterprise ceremony would
        // let an authenticator hand the Relying Party a tracking identifier it never asked for.
        if (attestationResult.EnterpriseAttestationSerialNumber is not null && originalOptions.Attestation is not AttestationConveyancePreference.Enterprise)
            throw new Fido2VerificationException(Fido2ErrorCode.UnexpectedEnterpriseAttestation, Fido2ErrorMessages.UnexpectedEnterpriseAttestation);

        // 23. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates)
        //     for that attestation type and attestation statement format fmt, from a trusted source or from policy.
        //     For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.

        MetadataBLOBPayloadEntry? metadataEntry = null;
        if (metadataService is IMetadataServiceAttestationCertificateLookup certificateLookupService)
            metadataEntry = await certificateLookupService.GetEntryAsync(authData.AttestedCredentialData.AaGuid, trustPath, cancellationToken);
        else if (metadataService != null)
            metadataEntry = await metadataService.GetEntryAsync(authData.AttestedCredentialData.AaGuid, cancellationToken);

        // while conformance testing, we must reject any authenticator that we cannot get metadata for
        if (metadataService?.ConformanceTesting() is true && metadataEntry is null && attType != AttestationType.None && AttestationObject.Fmt is not "fido-u2f")
            throw new Fido2VerificationException(Fido2ErrorCode.AaGuidNotFound, "AAGUID not found in MDS test metadata");

        TrustAnchor.Verify(metadataEntry, trustPath, metadataService?.ConformanceTesting() is true ? FidoValidationMode.FidoConformance2024 : FidoValidationMode.Default);

        // 24. Assess the attestation trustworthiness using the outputs of the verification procedure in step 22, as follows:
        //     If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
        //     If self attestation was used, verify that self attestation is acceptable under Relying Party policy.
        //     Otherwise, use the X.509 certificates returned as the attestation trust path from the verification
        //     procedure to verify that the attestation public key either correctly chains up to an acceptable root
        //     certificate, or is itself an acceptable certificate.

        // Check status reports for authenticator with undesirable status
        var latestStatusReport = metadataEntry?.GetLatestStatusReport();
        if (latestStatusReport != null && config.UndesiredAuthenticatorMetadataStatuses.Contains(latestStatusReport.Status))
        {
            throw new UndesiredMetadataStatusFido2VerificationException(latestStatusReport);
        }

        // 25. Verify that the credentialId is ≤ 1023 bytes.
        // Handled by AttestedCredentialData constructor

        // 26. Verify that the credentialId is not yet registered for any user. Level 3 widened this from Level 2's
        //     "any other user": "if the credentialId is already known then the Relying Party SHOULD fail this
        //     registration ceremony", including when it is already this user's, because an attacker who obtained
        //     a credential ID and public key could otherwise register a victim's credential as their own.

        if (await isCredentialIdUniqueToUser(new IsCredentialIdUniqueToUserParams(authData.AttestedCredentialData.CredentialId, originalOptions.User), cancellationToken) is false)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.NonUniqueCredentialId, Fido2ErrorMessages.NonUniqueCredentialId);
        }

        // 27/29. If the attestation statement attStmt verified successfully and is found to be trustworthy,
        //     then register the new credential with the account that was denoted in the options.user passed to create(),
        //     by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData,
        //     as appropriate for the Relying Party's system.

        // 24. If the attestation statement attStmt successfully verified but is not trustworthy per step 24 above,
        //     the Relying Party SHOULD fail the registration ceremony.
        //     This implementation throws if the outputs are not trustworthy for a particular attestation type.

        return new RegisteredPublicKeyCredential
        {
            Type = Raw.Type!.Value,
            Id = authData.AttestedCredentialData.CredentialId,
            RpId = originalOptions.Rp.Id,
            PublicKey = authData.AttestedCredentialData.CredentialPublicKey.GetBytes(),
            SignCount = authData.SignCount,
            Transports = Raw.Response.Transports,
            AuthenticatorAttachment = Raw.AuthenticatorAttachment,
            UvInitialized = authData.UserVerified,
            IsBackupEligible = authData.IsBackupEligible,
            IsBackedUp = authData.IsBackedUp,
            AttestationObject = Raw.Response.AttestationObject,
            AttestationClientDataJson = Raw.Response.ClientDataJson,
            User = originalOptions.User,
            AttestationFormat = AttestationObject.Fmt,
            AaGuid = authData.AttestedCredentialData.AaGuid,
            EnterpriseAttestationSerialNumber = attestationResult.EnterpriseAttestationSerialNumber,
            FirmwareVersion = attestationResult.FirmwareVersion,
            AuthenticatorExtensionResults = authData.Extensions?.Outputs ?? new AuthenticationExtensionsAuthenticatorOutputs()
        };
    }

    /// <summary>
    /// Validates extension inputs during registration ceremony.
    /// Ensures that extension input parameters are well-formed and don't violate constraints.
    /// </summary>
    private static void ValidateRegistrationExtensionInputs(AuthenticationExtensionsClientInputs? extensions)
    {
        if (extensions == null)
            return;

        // Validate PRF input structure
        if (extensions.PRF != null)
        {
            ClientExtensionValidation.ValidateRegistrationPRFInput(extensions.PRF);
        }

        // "If read or write is present: return a DOMException whose name is NotSupportedError." That holds
        // whether or not support was given -- support is itself optional during registration, so this
        // cannot be conditioned on it.
        if (extensions.LargeBlob is { } largeBlob)
        {
            if (largeBlob.Read)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    "The largeBlob extension's 'read' is not valid during registration. Use only during assertion.");
            }

            if (largeBlob.Write is not null)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    "The largeBlob extension's 'write' is not valid during registration. Use only during assertion.");
            }
        }

        // getCredBlob reads a blob back, which only an assertion can do.
        if (extensions.GetCredBlob.HasValue)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "The getCredBlob extension is not valid during registration. Use only during assertion.");
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
    /// Processes the extension outputs of a registration ceremony, per step 28 of WebAuthn Level 3 §7.1.
    /// </summary>
    /// <remarks>
    /// Level 3 no longer requires that every returned extension have been requested -- clients may add their
    /// own, and a Relying Party must cope -- so an output that was not asked for is rejected only when
    /// <paramref name="unsolicitedExtensionPolicy"/> says to. What is always checked is that the outputs of
    /// the extensions that <em>were</em> requested are well formed.
    /// </remarks>
    private static void ValidateExtensions(
        AuthenticationExtensionsClientInputs? requestedExtensions,
        AuthenticationExtensionsClientOutputs? clientExtensionResults,
        Extensions? authenticatorExtensions,
        UnsolicitedExtensionPolicy unsolicitedExtensionPolicy)
    {
        // Only validate extensions if some were explicitly requested
        if (requestedExtensions == null)
            return;

        // Get the set of requested extension identifiers
        var requestedIdentifiers = GetRequestedExtensionIdentifiers(requestedExtensions);

        // If no extensions were requested but some are available, validate
        if (requestedIdentifiers.Count == 0)
            return;

        // Validate client extension results
        if (clientExtensionResults != null)
        {
            if (unsolicitedExtensionPolicy is UnsolicitedExtensionPolicy.Reject)
            {
                var clientExtensionIdentifiers = GetClientExtensionResultIdentifiers(clientExtensionResults);
                foreach (var identifier in clientExtensionIdentifiers)
                {
                    if (!requestedIdentifiers.Contains(identifier))
                    {
                        throw new Fido2VerificationException(
                            Fido2ErrorCode.UnexpectedExtensions,
                            $"Extension '{identifier}' was returned but not requested in the registration options");
                    }
                }
            }

            // Validate extension output formats
            ValidateExtensionOutputs(requestedExtensions, clientExtensionResults);
        }

        // Validate authenticator extensions from authData
        if (unsolicitedExtensionPolicy is UnsolicitedExtensionPolicy.Reject && authenticatorExtensions != null && authenticatorExtensions.Length > 0)
        {
            var authenticatorExtensionIdentifiers = authenticatorExtensions.GetIdentifiers();
            foreach (var identifier in authenticatorExtensionIdentifiers)
            {
                if (!requestedIdentifiers.Contains(identifier))
                {
                    throw new Fido2VerificationException(
                        Fido2ErrorCode.UnexpectedExtensions,
                        $"Authenticator extension '{identifier}' was returned but not requested in the registration options");
                }
            }
        }
    }

    /// <summary>
    /// Validates the format and content of extension outputs. Each extension defines its own, in
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-defined-client-extensions">WebAuthn Level 3 §10.1</see>.
    /// </summary>
    private static void ValidateExtensionOutputs(
        AuthenticationExtensionsClientInputs requestedExtensions,
        AuthenticationExtensionsClientOutputs clientExtensionResults)
    {
        // Validate PRF extension output
        if (requestedExtensions.PRF != null && clientExtensionResults.PRF != null)
        {
            ClientExtensionValidation.ValidateRegistrationPRFOutput(clientExtensionResults.PRF);
        }


        // Validate extensions discovery (exts) output
#pragma warning disable CS0618 // uvm and exts were removed in L3; still honoured for Level 2 callers
        if (requestedExtensions.Extensions.HasValue && clientExtensionResults.Extensions != null)
        {
            ClientExtensionValidation.ValidateExtensionsDiscoveryOutput(clientExtensionResults.Extensions);
        }
#pragma warning restore CS0618

        // Validate LargeBlob extension output (registration context)
        if (requestedExtensions.LargeBlob?.Support != null && clientExtensionResults.LargeBlob != null)
        {
            ValidateLargeBlobRegistrationOutput(clientExtensionResults.LargeBlob);
        }

        // Validate credential protection policy output if requested
        if (requestedExtensions.CredentialProtectionPolicy.HasValue && clientExtensionResults.CredProtect.HasValue)
        {
            // CredProtect output should match a valid protection policy value
            var credProtect = clientExtensionResults.CredProtect.Value;
            if (!Enum.IsDefined(typeof(CredentialProtectionPolicy), credProtect))
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"Invalid credentialProtectionPolicy value returned: {credProtect}");
            }
        }

        // Validate minPinLength extension output if requested
        if (requestedExtensions.MinPinLength.HasValue && clientExtensionResults.MinPinLength.HasValue)
        {
            ValidateMinPinLengthOutput(clientExtensionResults.MinPinLength.Value);
        }
    }

    /// <summary>
    /// Validates minPinLength extension output. This is a CTAP2 authenticator extension, not a
    /// WebAuthn-defined one; see AuthenticationExtensionsClientOutputs.MinPinLength for the CTAP2 spec reference.
    /// </summary>
    private static void ValidateMinPinLengthOutput(uint minPinLength)
    {
        if (minPinLength is 0)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "minPinLength extension output must be a positive number");
        }
    }

    /// <summary>
    /// Validates the <c>largeBlob</c> extension output of a registration ceremony, whose only member is
    /// <c>supported</c> -- "only present in registration outputs".
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension"/>
    /// </remarks>
    private static void ValidateLargeBlobRegistrationOutput(AuthenticationExtensionsLargeBlobOutputs blobOutput)
    {
        // During registration, only 'supported' field is valid
        // 'blob' and 'written' should not be present
        if (blobOutput.Blob != null && blobOutput.Blob.Length > 0)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "LargeBlob extension output contains 'blob' field during registration. This field is only valid during assertion.");
        }

        if (blobOutput.Written)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "LargeBlob extension output contains 'written' field during registration. This field is only valid during assertion.");
        }
    }

    /// <summary>
    /// Extracts the set of requested extension identifiers from the registration options.
    /// </summary>
    private static HashSet<string> GetRequestedExtensionIdentifiers(AuthenticationExtensionsClientInputs? extensions)
    {
        var identifiers = new HashSet<string>(StringComparer.Ordinal);

        if (extensions == null)
            return identifiers;

        // Map properties to their JSON property names (extension identifiers)
        if (extensions.Example.HasValue)
            identifiers.Add("example.extension.bool");

#pragma warning disable CS0618 // uvm and exts were removed in L3; still honoured for Level 2 callers
        if (extensions.Extensions.HasValue)
            identifiers.Add("exts");
#pragma warning restore CS0618

        // Note: UserVerificationMethod has a private setter, so we skip checking if it was requested
        // as it's deprecated and unlikely to be explicitly set by new code

        if (extensions.CredProps.HasValue)
            identifiers.Add("credProps");

        if (extensions.PRF != null)
            identifiers.Add("prf");

        if (extensions.LargeBlob != null)
            identifiers.Add("largeBlob");

        if (extensions.CredentialProtectionPolicy.HasValue)
        {
            identifiers.Add("credentialProtectionPolicy");
            // credProtect is the output for credentialProtectionPolicy input
            identifiers.Add("credProtect");
        }

        if (extensions.EnforceCredentialProtectionPolicy.HasValue)
            identifiers.Add("enforceCredentialProtectionPolicy");

        if (!string.IsNullOrEmpty(extensions.AppIDExclude))
            identifiers.Add("appidExclude");

        if (extensions.MinPinLength.HasValue)
            identifiers.Add("minPinLength");

        if (extensions.CredBlob != null)
            identifiers.Add("credBlob");

        if (extensions.PinComplexityPolicy.HasValue)
            identifiers.Add("pinComplexityPolicy");

        return identifiers;
    }

    /// <summary>
    /// Extracts the set of extension identifiers from the client extension results.
    /// </summary>
    private static HashSet<string> GetClientExtensionResultIdentifiers(AuthenticationExtensionsClientOutputs clientExtensionResults)
    {
        var identifiers = new HashSet<string>(StringComparer.Ordinal);

        if (clientExtensionResults.Example.HasValue)
            identifiers.Add("example.extension.bool");

#pragma warning disable CS0618 // uvm and exts were removed in L3; still honoured for Level 2 callers
        if (clientExtensionResults.Extensions != null && clientExtensionResults.Extensions.Length > 0)
            identifiers.Add("exts");

        if (clientExtensionResults.UserVerificationMethod != null && clientExtensionResults.UserVerificationMethod.Length > 0)
            identifiers.Add("uvm");
#pragma warning restore CS0618

        if (clientExtensionResults.CredProps != null)
            identifiers.Add("credProps");

        if (clientExtensionResults.PRF != null)
            identifiers.Add("prf");

        if (clientExtensionResults.LargeBlob != null)
            identifiers.Add("largeBlob");

        if (clientExtensionResults.CredBlob.HasValue)
            identifiers.Add("credBlob");

        if (clientExtensionResults.CredProtect.HasValue)
            identifiers.Add("credProtect");

        // Note: credProtect is the output for credentialProtectionPolicy input
        if (clientExtensionResults.CredProtect.HasValue)
            identifiers.Add("credentialProtectionPolicy");

        if (clientExtensionResults.AppIDExclude)
            identifiers.Add("appidExclude");

        if (clientExtensionResults.MinPinLength.HasValue)
            identifiers.Add("minPinLength");

        return identifiers;
    }

    /// <summary>
    /// The AttestationObject after CBOR parsing
    /// </summary>
    public sealed class ParsedAttestationObject(string fmt, CborObject attStmt, AuthenticatorData authData)
    {
        public string Fmt { get; } = fmt;

        /// <summary>
        /// The attestation statement. This is a <see cref="CborMap"/> for every format defined by WebAuthn except
        /// <c>compound</c>, whose statement is a <see cref="CborArray"/> of sub-statements.
        /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation"/>
        /// </summary>
        public CborObject AttStmt { get; } = attStmt;

        public AuthenticatorData AuthData { get; } = authData;

        internal static ParsedAttestationObject FromCbor(CborMap cbor)
        {
            if (!(
                cbor["fmt"] is CborTextString fmt &&
                cbor["attStmt"] is CborMap or CborArray &&
                cbor["authData"] is CborByteString authData))
            {
                throw new Fido2VerificationException(Fido2ErrorCode.MalformedAttestationObject, Fido2ErrorMessages.MalformedAttestationObject);
            }

            return new ParsedAttestationObject(
                fmt: fmt,
                attStmt: cbor["attStmt"]!,
                authData: AuthenticatorData.Parse(authData)
            );
        }
    }
}
