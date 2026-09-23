using System;
using System.Collections.Generic;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Moq;

namespace Test;

/// <summary>
/// Covers registration-ceremony validation branches of <see cref="AuthenticatorAttestationResponse.VerifyAsync"/>
/// that the per-format attestation tests (Tests/Fido2.Tests/Attestation/*) and the other L3* registration
/// tests don't reach: the malformed-id/backup-flag/algorithm checks, the non-map attStmt rejection, the
/// credentialProtectionPolicy input/output validation, the largeBlob/minPinLength registration outputs, and
/// the extension-identifier extraction helpers.
/// </summary>
public class L3RegistrationResponseValidationTests : Fido2Tests.Attestation
{
    public L3RegistrationResponseValidationTests()
    {
        _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborMap() } };
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
    }

    [Fact]
    public async Task AnIdThatDoesNotDecodeToRawIdIsRejectedAsync()
    {
        // "8dA" is valid base64url, but it doesn't decode to [0xbe, 0xef] -- the mismatch branch of the
        // id/rawId cross-check, distinct from a not-valid-base64url id.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, id: "8dA", rawId: [0xbe, 0xef]));

        Assert.Equal(Fido2ErrorCode.InvalidAttestationResponse, ex.Code);
    }

    [Fact]
    public async Task AnAlgorithmNotAmongPubKeyCredParamsIsRejectedAsync()
    {
        // The harness' credential public key uses _validCOSEParameters[0] (ES256); offering only RS256
        // means the credential's algorithm was never one the Relying Party asked for.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, pubKeyCredParams: [new PubKeyCredParam(COSE.Algorithm.RS256)]));

        Assert.Equal(Fido2ErrorCode.CredentialAlgorithmRequirementNotMet, ex.Code);
    }

    [Fact]
    public async Task ConformanceTestingRejectsANonNoneAttestationMissingFromMetadataAsync()
    {
        // Self attestation ("packed" without x5c) is not AttestationType.None, and "packed" is not the
        // "fido-u2f" carve-out, so a conformance-testing metadata service that cannot find the AAGUID must
        // reject the registration outright.
        var (kty, alg, crv) = Fido2Tests._validCOSEParameters[0];
        _attestationObject = new CborMap
        {
            { "fmt", "packed" },
            { "attStmt", new CborMap { { "alg", alg }, { "sig", SignData(kty, alg, crv) } } }
        };

        var metadataService = new Mock<IMetadataService>();
        metadataService.Setup(m => m.ConformanceTesting()).Returns(true);
        metadataService.Setup(m => m.GetEntryAsync(It.IsAny<Guid>(), It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync((MetadataBLOBPayloadEntry)null);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, metadataService: metadataService.Object));

        Assert.Equal(Fido2ErrorCode.AaGuidNotFound, ex.Code);
    }

    [Fact]
    public async Task ABackupStateWithoutBackupEligibilityIsRejectedAsync()
    {
        // BS set but BE clear is malformed regardless of Relying Party policy: a credential that isn't
        // backup eligible can never be backed up.
        _flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BS;

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidBackupFlags, ex.Code);
    }

    [Fact]
    public async Task ANonMapAttStmtIsRejectedForANonCompoundFormatAsync()
    {
        // Every non-"compound" format's attStmt must be a CBOR map; a CBOR array here is what "compound"
        // would carry, but this object claims to be "none".
        _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborArray() } };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.InvalidAttestationStatement, ex.Message);
    }

    [Fact]
    public async Task AnInvalidCredentialProtectionPolicyInputIsRejectedAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                new AuthenticationExtensionsClientInputs { CredentialProtectionPolicy = (CredentialProtectionPolicy)99 }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("credentialProtectionPolicy", ex.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARequestWithNoRecognizedExtensionsShortCircuitsValidationAsync()
    {
        // requestedExtensions is non-null but every member is unset, so GetRequestedExtensionIdentifiers
        // returns an empty set and ValidateExtensions returns before looking at the client/authenticator
        // extension results at all.
        var credential = await MakeAttestationResponseAsync(new AuthenticationExtensionsClientInputs());

        Assert.Equal(_credentialID, credential.Id);
    }

    [Fact]
    public async Task AnUnrequestedAuthenticatorExtensionIsRejectedWhenConfiguredAsync()
    {
        // The client-extension-results Reject check would fire first on the harness' default (unsolicited)
        // client extension results, so use a clean one here to isolate the *authenticator* extension check.
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs();
        _authenticatorExtensions = new CborMap { { "testing", true } };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(new AuthenticationExtensionsClientInputs { CredProps = true }, UnsolicitedExtensionPolicy.Reject));

        Assert.Equal(Fido2ErrorCode.UnexpectedExtensions, ex.Code);
        Assert.Contains("Authenticator extension", ex.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task ALargeBlobSupportedOutputIsAcceptedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs
        {
            LargeBlob = new AuthenticationExtensionsLargeBlobOutputs { Supported = true }
        };

        var credential = await MakeAttestationResponseAsync(
            new AuthenticationExtensionsClientInputs { LargeBlob = new AuthenticationExtensionsLargeBlobInputs { Support = LargeBlobSupport.Preferred } });

        Assert.Equal(_credentialID, credential.Id);
    }

    [Fact]
    public async Task ALargeBlobOutputCarryingABlobDuringRegistrationIsRejectedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs
        {
            LargeBlob = new AuthenticationExtensionsLargeBlobOutputs { Blob = [0xca, 0xfe] }
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                new AuthenticationExtensionsClientInputs { LargeBlob = new AuthenticationExtensionsLargeBlobInputs { Support = LargeBlobSupport.Preferred } }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("'blob'", ex.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task ALargeBlobOutputCarryingWrittenDuringRegistrationIsRejectedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs
        {
            LargeBlob = new AuthenticationExtensionsLargeBlobOutputs { Written = true }
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                new AuthenticationExtensionsClientInputs { LargeBlob = new AuthenticationExtensionsLargeBlobInputs { Support = LargeBlobSupport.Preferred } }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("'written'", ex.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnInvalidCredentialProtectionPolicyOutputIsRejectedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { CredProtect = (CredentialProtectionPolicy)99 };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                new AuthenticationExtensionsClientInputs { CredentialProtectionPolicy = CredentialProtectionPolicy.UserVerificationOptional }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("credentialProtectionPolicy value returned", ex.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task AZeroMinPinLengthOutputIsRejectedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { MinPinLength = 0 };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                new AuthenticationExtensionsClientInputs { MinPinLength = true }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("positive number", ex.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task APositiveMinPinLengthOutputIsAcceptedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { MinPinLength = 6 };

        var credential = await MakeAttestationResponseAsync(
            new AuthenticationExtensionsClientInputs { MinPinLength = true });

        Assert.Equal(_credentialID, credential.Id);
    }

    [Fact]
    public async Task EveryRequestedExtensionIdentifierIsExtractedAsync()
    {
        // Exercises GetRequestedExtensionIdentifiers' remaining Add() calls: example.extension.bool,
        // credentialProtectionPolicy/credProtect, enforceCredentialProtectionPolicy, appidExclude,
        // minPinLength. Ignore policy means the (unrelated, unsolicited) default client extension
        // results and authenticator extensions don't matter here.
        var credential = await MakeAttestationResponseAsync(new AuthenticationExtensionsClientInputs
        {
            Example = true,
            CredentialProtectionPolicy = CredentialProtectionPolicy.UserVerificationOptional,
            EnforceCredentialProtectionPolicy = true,
            AppIDExclude = "https://example.com",
            MinPinLength = true
        });

        Assert.Equal(_credentialID, credential.Id);
    }

    [Fact]
    public async Task EveryClientExtensionResultIdentifierIsExtractedAsync()
    {
        // Exercises GetClientExtensionResultIdentifiers, which only runs under Reject -- every requested
        // identifier here has a matching client-result identifier, and the (empty) authenticator
        // extensions block means the separate authenticator-extension check has nothing to reject either.
        _authenticatorExtensions = new CborMap();
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs
        {
            CredProps = new CredentialPropertiesOutput { Rk = true },
            PRF = new AuthenticationExtensionsPRFOutputs { Enabled = true },
            LargeBlob = new AuthenticationExtensionsLargeBlobOutputs { Supported = true },
            CredBlob = true,
            CredProtect = CredentialProtectionPolicy.UserVerificationOptional,
            AppIDExclude = true,
            MinPinLength = 6,
        };

        var credential = await MakeAttestationResponseAsync(
            new AuthenticationExtensionsClientInputs
            {
                CredProps = true,
                PRF = new AuthenticationExtensionsPRFInputs(),
                LargeBlob = new AuthenticationExtensionsLargeBlobInputs { Support = LargeBlobSupport.Preferred },
                CredBlob = [0x01],
                CredentialProtectionPolicy = CredentialProtectionPolicy.UserVerificationOptional,
                AppIDExclude = "https://example.com",
                MinPinLength = true,
            },
            UnsolicitedExtensionPolicy.Reject);

        Assert.Equal(_credentialID, credential.Id);
    }
}
