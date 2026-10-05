using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Moq;

namespace Test;

/// <summary>
/// Covers <see cref="Fido2Configuration.AaguidDenyList"/>/<see cref="Fido2Configuration.AaguidAllowList"/>
/// enforcement in <see cref="AuthenticatorAttestationResponse.VerifyAsync"/> (registration) and
/// <see cref="AuthenticatorAssertionResponse"/>'s <c>VerifyAsync</c>
/// (assertion, deny list only), including <see cref="Fido2Configuration.AaguidAllowListRequiresAttestation"/>:
/// an allow-listed AAGUID only counts when the attestation proves it.
/// </summary>
public class AaguidPolicyTests : Fido2Tests.Attestation
{
    public AaguidPolicyTests()
    {
        _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborMap() } };
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
    }

    [Fact]
    public async Task RegistrationIsRejectedWhenAaguidIsOnTheDenyListAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, configure: config => config.AaguidDenyList = [_aaguid]));

        Assert.Equal(Fido2ErrorCode.AaguidDenied, ex.Code);
    }

    [Fact]
    public async Task RegistrationIsRejectedWhenAaguidIsNotOnANonEmptyAllowListAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, configure: config => config.AaguidAllowList = [Guid.NewGuid()]));

        Assert.Equal(Fido2ErrorCode.AaguidNotAllowed, ex.Code);
    }

    [Fact]
    public async Task AnAllowListedAaguidUnderNoneAttestationIsRejectedByDefaultAsync()
    {
        // "none" attestation proves nothing about the AAGUID: any software authenticator can claim it.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, configure: config => config.AaguidAllowList = [_aaguid]));

        Assert.Equal(Fido2ErrorCode.AaguidNotAttested, ex.Code);
    }

    [Fact]
    public async Task AnAllowListedAaguidUnderNoneAttestationIsAcceptedWhenAttestationIsNotRequiredAsync()
    {
        var result = await MakeAttestationResponseAsync(null, configure: config =>
        {
            config.AaguidAllowList = [_aaguid];
            config.AaguidAllowListRequiresAttestation = false;
        });

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task AnAllowListedAaguidWhoseChainValidatesAgainstItsMetadataIsAcceptedAsync()
    {
        using var root = CreateRoot(out var rootKey);
        UseFullPackedAttestation(root, rootKey);

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.AaguidAllowList = [_aaguid],
            metadataService: MetadataServiceFor(["basic_full"], root).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task AnAllowListedAaguidWithAValidChainButNoMetadataIsRejectedAsync()
    {
        // The chain verifies against the certificate the authenticator sent, but nothing ties that root to the
        // model the AAGUID names.
        using var root = CreateRoot(out var rootKey);
        UseFullPackedAttestation(root, rootKey);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, configure: config => config.AaguidAllowList = [_aaguid]));

        Assert.Equal(Fido2ErrorCode.AaguidNotAttested, ex.Code);
    }

    [Fact]
    public async Task AnAllowListedAaguidWhoseMetadataDeclaresOnlyAnonCaIsRejectedAsync()
    {
        // TrustAnchor does not validate an AnonCA chain against the statement, so the AAGUID is not proven.
        using var root = CreateRoot(out var rootKey);
        UseFullPackedAttestation(root, rootKey);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                null,
                configure: config => config.AaguidAllowList = [_aaguid],
                metadataService: MetadataServiceFor(["anonca"], root).Object));

        Assert.Equal(Fido2ErrorCode.AaguidNotAttested, ex.Code);
    }

    [Fact]
    public async Task AnAllowListedAaguidWhoseMetadataHasNoAttestationTypesIsRejectedAsync()
    {
        using var root = CreateRoot(out var rootKey);
        UseFullPackedAttestation(root, rootKey);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                null,
                configure: config => config.AaguidAllowList = [_aaguid],
                metadataService: MetadataServiceFor(null, root).Object));

        Assert.Equal(Fido2ErrorCode.AaguidNotAttested, ex.Code);
    }

    [Fact]
    public async Task AnAllowListedAaguidUnderSelfAttestationIsRejectedEvenWhenMetadataAllowsSurrogateAsync()
    {
        var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
        _attestationObject = new CborMap { { "fmt", "packed" } };
        _attestationObject.Add("attStmt", new CborMap { { "alg", alg }, { "sig", SignData(type, alg, crv) } });

        using var root = CreateRoot(out _);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                null,
                configure: config => config.AaguidAllowList = [_aaguid],
                metadataService: MetadataServiceFor(["basic_surrogate"], root).Object));

        Assert.Equal(Fido2ErrorCode.AaguidNotAttested, ex.Code);
    }

    [Fact]
    public async Task ThePublicTrustAnchorOverloadStillChecksTheTrustPathAsync()
    {
        // TrustAnchor.Verify keeps its public contract; the ceremony now uses the internal variant that also
        // reports whether the chain was validated.
        using var root = CreateRoot(out _);
        using var unrelated = CreateRoot(out _);
        var entry = await MetadataServiceFor(["basic_full"], root).Object.GetEntryAsync(_aaguid);

        var ex = Assert.Throws<Fido2VerificationException>(() => TrustAnchor.Verify(entry, [unrelated], AttestationType.Basic));

        Assert.Equal(Fido2ErrorCode.InvalidCertificateChain, ex.Code);

        // With no metadata there is nothing to check against.
        TrustAnchor.Verify(null, [unrelated], AttestationType.Basic);
    }

    [Fact]
    public async Task RegistrationSucceedsWhenNeitherListIsConfiguredAsync()
    {
        var result = await MakeAttestationResponseAsync(null);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    private X509Certificate2 CreateRoot(out ECDsa rootKey)
    {
        rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest(rootDN, rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);
        return rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
    }

    /// <summary>
    /// A packed attestation signed by an attestation certificate issued by <paramref name="root"/>, carrying this
    /// test's AAGUID in its id-fido-gen-ce-aaguid extension. The x5c holds the attestation certificate only; the
    /// root is what a metadata statement would supply.
    /// </summary>
    private void UseFullPackedAttestation(X509Certificate2 root, ECDsa rootKey)
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];

        using var attestationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US"),
            attestationKey,
            HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(notCAExt);
        request.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        using var attestationCertificate = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2), RandomNumberGenerator.GetBytes(12));

        _attestationObject = new CborMap { { "fmt", "packed" } };
        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", SignData(type, alg, curve, ecdsa: attestationKey) },
            { "x5c", new CborArray { attestationCertificate.RawData } }
        });
    }

    private Mock<IMetadataService> MetadataServiceFor(string[] attestationTypes, X509Certificate2 root)
    {
        var metadataService = new Mock<IMetadataService>();
        metadataService.Setup(m => m.ConformanceTesting()).Returns(false);
        metadataService
            .Setup(m => m.GetEntryAsync(_aaguid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MetadataBLOBPayloadEntry
            {
                AaGuid = _aaguid,
                StatusReports = [],
                MetadataStatement = new MetadataStatement
                {
                    AttestationTypes = attestationTypes,
                    AttestationRootCertificates = [Convert.ToBase64String(root.RawData)]
                }
            });
        return metadataService;
    }

    [Fact]
    public async Task AssertionIsRejectedWhenTheStoredAaguidIsOnTheDenyListAsync()
    {
        var deniedAaguid = Guid.NewGuid();

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                null,
                config: new Fido2Configuration
                {
                    RPID = L3AssertionHarness.Rp,
                    RPName = L3AssertionHarness.Rp,
                    Origins = new HashSet<string> { L3AssertionHarness.Rp },
                    AaguidDenyList = [deniedAaguid]
                },
                storedAaGuid: deniedAaguid));

        Assert.Equal(Fido2ErrorCode.AaguidDenied, ex.Code);
    }

    [Fact]
    public async Task AssertionSucceedsWhenTheStoredAaguidIsNotOnTheDenyListAsync()
    {
        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: new Fido2Configuration
            {
                RPID = L3AssertionHarness.Rp,
                RPName = L3AssertionHarness.Rp,
                Origins = new HashSet<string> { L3AssertionHarness.Rp },
                AaguidDenyList = [Guid.NewGuid()]
            },
            storedAaGuid: Guid.NewGuid());

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task ThePreAaguidVerifyAsyncOverloadStillVerifiesAsync()
    {
        // Binary compatibility: the overload without storedAaGuid keeps its signature, and simply applies no
        // AAGUID policy.
        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: new Fido2Configuration
            {
                RPID = L3AssertionHarness.Rp,
                RPName = L3AssertionHarness.Rp,
                Origins = new HashSet<string> { L3AssertionHarness.Rp },
                AaguidDenyList = [Guid.NewGuid()]
            },
            viaPreAaguidOverload: true);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task AssertionSucceedsWhenNoStoredAaguidIsSuppliedEvenWithADenyListAsync()
    {
        // A Relying Party that doesn't track AAGUID per credential can't be retroactively blocked by it.
        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: new Fido2Configuration
            {
                RPID = L3AssertionHarness.Rp,
                RPName = L3AssertionHarness.Rp,
                Origins = new HashSet<string> { L3AssertionHarness.Rp },
                AaguidDenyList = [Guid.NewGuid()]
            });

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }
}
