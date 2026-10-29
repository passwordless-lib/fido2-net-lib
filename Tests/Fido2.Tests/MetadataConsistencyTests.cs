using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Moq;

namespace Test;

/// <summary>
/// Covers <see cref="Fido2Configuration.MetadataConsistencyStrictness"/>: every check it gates (backup
/// eligibility, algorithm, credential ID length, discoverability, transports, extensions) and how the four
/// strictness levels change which of those checks can reject a registration.
/// </summary>
public class MetadataConsistencyTests : Fido2Tests.Attestation
{
    public MetadataConsistencyTests()
    {
        _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborMap() } };
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]); // ES256
        // Not backup-eligible by default, so tests for the other checks don't incidentally also trip the
        // backup-eligibility check over an unset MultiDeviceCredentialSupport. Set explicitly where relevant.
        _flags = DefaultFlags;
    }

    private Mock<IMetadataService> MockMetadataService(MetadataStatement statement)
    {
        var metadataService = new Mock<IMetadataService>();
        metadataService.Setup(m => m.ConformanceTesting()).Returns(false);
        metadataService
            .Setup(m => m.GetEntryAsync(_aaguid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MetadataBLOBPayloadEntry
            {
                AaGuid = _aaguid,
                StatusReports = [],
                MetadataStatement = statement
            });
        return metadataService;
    }

    private Mock<IMetadataService> MockMetadataService(string multiDeviceCredentialSupport) =>
        MockMetadataService(new MetadataStatement { MultiDeviceCredentialSupport = multiDeviceCredentialSupport });

    #region Backup eligibility (weak tier)

    [Theory]
    [InlineData("unsupported")]
    [InlineData(null)] // "If this multiDeviceCredentialSupport field is missing the implicit value is 'unsupported'"
    public async Task ABackupEligibleCredentialIsRejectedAtStrictWhenMetadataSaysUnsupportedAsync(string multiDeviceCredentialSupport)
    {
        _flags = DefaultFlags | AuthenticatorFlags.BE;

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                null,
                configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict,
                metadataService: MockMetadataService(multiDeviceCredentialSupport).Object));

        Assert.Equal(Fido2ErrorCode.BackupEligibilityNotDeclaredInMetadata, ex.Code);
    }

    [Fact]
    public async Task ABackupEligibleCredentialIsOnlyLoggedAtStandardWhenMetadataSaysUnsupportedAsync()
    {
        // Weak tier: Standard (the default) logs the disagreement but does not reject it, since most live-BLOB
        // statements predate multiDeviceCredentialSupport and would otherwise be rejected by default.
        _flags = DefaultFlags | AuthenticatorFlags.BE;
        var logger = new ListLogger<Fido2>();

        var result = await MakeAttestationResponseAsync(
            null,
            metadataService: MockMetadataService("unsupported").Object,
            logger: logger);

        Assert.Equal(_aaguid, result.AaGuid);
        Assert.Single(logger.WithEventId(1206));
        Assert.Empty(logger.WithEventId(1207));
    }

    [Theory]
    [InlineData("explicit")]
    [InlineData("implicit")]
    [InlineData("some-future-value")]
    public async Task ABackupEligibleCredentialIsAcceptedAtStrictWhenMetadataDeclaresSupportAsync(string multiDeviceCredentialSupport)
    {
        // The values FIDO Metadata Statement v3.1 defines; the live BLOB uses "explicit". An unknown future value
        // is not a contradiction the library can recognise.
        _flags = DefaultFlags | AuthenticatorFlags.BE;

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict,
            metadataService: MockMetadataService(multiDeviceCredentialSupport).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task ABackupEligibleCredentialFromAModelWithNoMetadataIsAcceptedAtStrictAsync()
    {
        // Most synced passkey providers have no MDS statement; with no statement there is no claim to contradict.
        _flags = DefaultFlags | AuthenticatorFlags.BE;
        var metadataService = new Mock<IMetadataService>();
        metadataService.Setup(m => m.ConformanceTesting()).Returns(false);

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict,
            metadataService: metadataService.Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task ABackupEligibleCredentialIsAcceptedAtStrictWithoutAMetadataServiceAsync()
    {
        _flags = DefaultFlags | AuthenticatorFlags.BE;

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task ANonBackupEligibleCredentialIsAcceptedAtStrictEvenWhenMetadataSaysUnsupportedAsync()
    {
        _flags = DefaultFlags;

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict,
            metadataService: MockMetadataService("unsupported").Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    #endregion

    #region Algorithm (strong tier)

    [Fact]
    public async Task ACredentialIsRejectedAtStandardWhenItsAlgorithmIsNotDeclaredInMetadataAsync()
    {
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Algorithms = [new PubKeyCredParam(COSE.Algorithm.RS256)] }
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, metadataService: MockMetadataService(statement).Object));

        Assert.Equal(Fido2ErrorCode.AlgorithmNotDeclaredInMetadata, ex.Code);
    }

    [Fact]
    public async Task ACredentialIsAcceptedWhenItsAlgorithmIsDeclaredInMetadataAsync()
    {
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Algorithms = [new PubKeyCredParam(COSE.Algorithm.ES256), new PubKeyCredParam(COSE.Algorithm.RS256)] }
        };

        var result = await MakeAttestationResponseAsync(null, metadataService: MockMetadataService(statement).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task ACredentialIsAcceptedWhenMetadataDeclaresNoAuthenticatorGetInfoAsync()
    {
        // UAF/U2F statements, and platform API-only FIDO2 statements, have no authenticatorGetInfo and so make
        // no claim this check can contradict.
        var result = await MakeAttestationResponseAsync(null, metadataService: MockMetadataService(new MetadataStatement()).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task AnAlgorithmMismatchIsIgnoredWhenStrictnessIsOffAsync()
    {
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Algorithms = [new PubKeyCredParam(COSE.Algorithm.RS256)] }
        };

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Off,
            metadataService: MockMetadataService(statement).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task AnAlgorithmMismatchIsLoggedButNotBlockedWhenStrictnessIsLogOnlyAsync()
    {
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Algorithms = [new PubKeyCredParam(COSE.Algorithm.RS256)] }
        };
        var logger = new ListLogger<Fido2>();

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.LogOnly,
            metadataService: MockMetadataService(statement).Object,
            logger: logger);

        Assert.Equal(_aaguid, result.AaGuid);
        Assert.Single(logger.WithEventId(1206));
        Assert.Empty(logger.WithEventId(1207));
    }

    #endregion

    #region Credential ID length (strong tier)

    [Fact]
    public async Task ACredentialIsRejectedAtStandardWhenItsIdExceedsTheDeclaredMaximumAsync()
    {
        _credentialID = RandomNumberGenerator.GetBytes(32);
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { MaxCredentialIdLength = 16 }
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, metadataService: MockMetadataService(statement).Object));

        Assert.Equal(Fido2ErrorCode.CredentialIdExceedsMetadataMaximum, ex.Code);
    }

    [Fact]
    public async Task ACredentialIsAcceptedWhenItsIdIsWithinTheDeclaredMaximumAsync()
    {
        _credentialID = RandomNumberGenerator.GetBytes(16);
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { MaxCredentialIdLength = 16 }
        };

        var result = await MakeAttestationResponseAsync(null, metadataService: MockMetadataService(statement).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    #endregion

    #region Discoverability (strong tier)

    [Fact]
    public async Task ADiscoverableCredentialIsRejectedAtStandardWhenMetadataSaysRkIsUnsupportedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { CredProps = new CredentialPropertiesOutput { Rk = true } };
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Options = new Dictionary<string, bool> { ["rk"] = false } }
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, metadataService: MockMetadataService(statement).Object));

        Assert.Equal(Fido2ErrorCode.DiscoverableCredentialNotDeclaredInMetadata, ex.Code);
    }

    [Fact]
    public async Task ADiscoverableCredentialIsAcceptedWhenMetadataDeclaresRkSupportedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { CredProps = new CredentialPropertiesOutput { Rk = true } };
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Options = new Dictionary<string, bool> { ["rk"] = true } }
        };

        var result = await MakeAttestationResponseAsync(null, metadataService: MockMetadataService(statement).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task ADiscoverableCredentialIsAcceptedWhenMetadataIsSilentAboutRkAsync()
    {
        // No "rk" key at all is not a claim either way -- only an explicit false contradicts credProps.rk=true.
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { CredProps = new CredentialPropertiesOutput { Rk = true } };
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Options = new Dictionary<string, bool>() }
        };

        var result = await MakeAttestationResponseAsync(null, metadataService: MockMetadataService(statement).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    #endregion

    #region Transports (weak tier)

    [Fact]
    public async Task AnUndeclaredTransportIsOnlyLoggedAtStandardAsync()
    {
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Transports = ["usb"] }
        };
        var logger = new ListLogger<Fido2>();

        var result = await MakeAttestationResponseAsync(
            null,
            metadataService: MockMetadataService(statement).Object,
            transports: [AuthenticatorTransport.Internal],
            logger: logger);

        Assert.Equal(_aaguid, result.AaGuid);
        Assert.Single(logger.WithEventId(1206));
        Assert.Empty(logger.WithEventId(1207));
    }

    [Fact]
    public async Task AnUndeclaredTransportIsRejectedAtStrictAsync()
    {
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Transports = ["usb"] }
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                null,
                configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict,
                metadataService: MockMetadataService(statement).Object,
                transports: [AuthenticatorTransport.Internal]));

        Assert.Equal(Fido2ErrorCode.TransportNotDeclaredInMetadata, ex.Code);
    }

    [Fact]
    public async Task ADeclaredTransportIsAcceptedAtStrictAsync()
    {
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Transports = ["usb", "nfc"] }
        };

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict,
            metadataService: MockMetadataService(statement).Object,
            transports: [AuthenticatorTransport.Usb]);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    #endregion

    #region Extensions (weak tier)

    [Fact]
    public async Task AnUndeclaredExtensionIsOnlyLoggedAtStandardAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { CredProtect = CredentialProtectionPolicy.UserVerificationOptional };
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Extensions = ["hmac-secret"] }
        };
        var logger = new ListLogger<Fido2>();

        var result = await MakeAttestationResponseAsync(null, metadataService: MockMetadataService(statement).Object, logger: logger);

        Assert.Equal(_aaguid, result.AaGuid);
        Assert.Single(logger.WithEventId(1206));
        Assert.Empty(logger.WithEventId(1207));
    }

    [Fact]
    public async Task AnUndeclaredExtensionIsRejectedAtStrictAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { CredProtect = CredentialProtectionPolicy.UserVerificationOptional };
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Extensions = ["hmac-secret"] }
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(
                null,
                configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict,
                metadataService: MockMetadataService(statement).Object));

        Assert.Equal(Fido2ErrorCode.ExtensionNotDeclaredInMetadata, ex.Code);
    }

    [Fact]
    public async Task ADeclaredExtensionViaSupportedExtensionsIsAcceptedAtStrictAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { CredProtect = CredentialProtectionPolicy.UserVerificationOptional };
        var statement = new MetadataStatement
        {
            SupportedExtensions = [new ExtensionDescriptor { Id = "credProtect" }]
        };

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict,
            metadataService: MockMetadataService(statement).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task APrfOutputMatchesHmacSecretInMetadataAtStrictAsync()
    {
        // WebAuthn "prf" is implemented over CTAP2 "hmac-secret"; the metadata declares the latter.
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { PRF = new AuthenticationExtensionsPRFOutputs() };
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Extensions = ["hmac-secret"] }
        };

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict,
            metadataService: MockMetadataService(statement).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    [Fact]
    public async Task ClientOnlyExtensionOutputsAreNeverCheckedAgainstMetadataAsync()
    {
        // credProps is never declared by an authenticator statement; it describes what the client observed.
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { CredProps = new CredentialPropertiesOutput { Rk = false } };
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Extensions = [] }
        };

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Strict,
            metadataService: MockMetadataService(statement).Object);

        Assert.Equal(_aaguid, result.AaGuid);
    }

    #endregion

    #region Strictness levels

    [Fact]
    public async Task OffSkipsEveryCheckIncludingStrongTierOnesAsync()
    {
        _credentialID = RandomNumberGenerator.GetBytes(32);
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo
            {
                Algorithms = [new PubKeyCredParam(COSE.Algorithm.RS256)],
                MaxCredentialIdLength = 16
            }
        };
        var logger = new ListLogger<Fido2>();

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.Off,
            metadataService: MockMetadataService(statement).Object,
            logger: logger);

        Assert.Equal(_aaguid, result.AaGuid);
        Assert.Empty(logger.WithEventId(1206));
    }

    [Fact]
    public async Task LogOnlyNeverBlocksEvenAStrongTierMismatchAsync()
    {
        _credentialID = RandomNumberGenerator.GetBytes(32);
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo { MaxCredentialIdLength = 16 }
        };
        var logger = new ListLogger<Fido2>();

        var result = await MakeAttestationResponseAsync(
            null,
            configure: config => config.MetadataConsistencyStrictness = MetadataConsistencyStrictness.LogOnly,
            metadataService: MockMetadataService(statement).Object,
            logger: logger);

        Assert.Equal(_aaguid, result.AaGuid);
        Assert.Single(logger.WithEventId(1206));
        Assert.Empty(logger.WithEventId(1207));
    }

    #endregion
}
