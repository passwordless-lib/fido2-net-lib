using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Moq;

namespace Test;

/// <summary>
/// Covers the assertion-time half of <see cref="Fido2Configuration.MetadataConsistencyStrictness"/>: backup
/// state, authenticator attachment (the closest available proxy for a per-assertion transport check -- WebAuthn
/// has no <c>getTransports()</c> equivalent on an assertion response), and extensions.
/// </summary>
public class AssertionMetadataConsistencyTests
{
    private static readonly Guid Aaguid = Guid.NewGuid();

    private static Mock<IMetadataService> MockMetadataService(MetadataStatement statement)
    {
        var metadataService = new Mock<IMetadataService>();
        metadataService
            .Setup(m => m.GetEntryAsync(Aaguid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MetadataBLOBPayloadEntry { AaGuid = Aaguid, StatusReports = [], MetadataStatement = statement });
        return metadataService;
    }

    private static Fido2Configuration Config(MetadataConsistencyStrictness strictness) => new()
    {
        RPID = L3AssertionHarness.Rp,
        RPName = L3AssertionHarness.Rp,
        Origins = new HashSet<string> { L3AssertionHarness.Rp },
        MetadataConsistencyStrictness = strictness
    };

    #region Backup state (weak tier)

    [Fact]
    public async Task ABackedUpAssertionIsOnlyLoggedAtStandardWhenMetadataSaysUnsupportedAsync()
    {
        var logger = new ListLogger<Fido2>();

        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(MetadataConsistencyStrictness.Standard),
            storedAaGuid: Aaguid,
            metadataService: MockMetadataService(new MetadataStatement { MultiDeviceCredentialSupport = "unsupported" }).Object,
            logger: logger,
            flags: AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE | AuthenticatorFlags.BS);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
        Assert.Single(logger.WithEventId(1206));
        Assert.Empty(logger.WithEventId(1207));
    }

    [Fact]
    public async Task ABackedUpAssertionIsRejectedAtStrictWhenMetadataSaysUnsupportedAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                null,
                config: Config(MetadataConsistencyStrictness.Strict),
                storedAaGuid: Aaguid,
                metadataService: MockMetadataService(new MetadataStatement { MultiDeviceCredentialSupport = "unsupported" }).Object,
                flags: AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE | AuthenticatorFlags.BS));

        Assert.Equal(Fido2ErrorCode.BackupStateNotDeclaredInMetadata, ex.Code);
    }

    [Fact]
    public async Task ABackedUpAssertionIsAcceptedAtStrictWhenMetadataDeclaresSupportAsync()
    {
        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(MetadataConsistencyStrictness.Strict),
            storedAaGuid: Aaguid,
            metadataService: MockMetadataService(new MetadataStatement { MultiDeviceCredentialSupport = "explicit" }).Object,
            flags: AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE | AuthenticatorFlags.BS);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task ANonBackedUpAssertionIsAcceptedAtStrictEvenWhenMetadataSaysUnsupportedAsync()
    {
        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(MetadataConsistencyStrictness.Strict),
            storedAaGuid: Aaguid,
            metadataService: MockMetadataService(new MetadataStatement { MultiDeviceCredentialSupport = "unsupported" }).Object);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    #endregion

    #region Attachment (weak tier)

    [Fact]
    public async Task APlatformAttachmentIsRejectedAtStrictWhenMetadataDeclaresOnlyExternalTransportsAsync()
    {
        var statement = new MetadataStatement { AuthenticatorGetInfo = new AuthenticatorGetInfo { Transports = ["usb", "nfc"] } };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                null,
                config: Config(MetadataConsistencyStrictness.Strict),
                storedAaGuid: Aaguid,
                metadataService: MockMetadataService(statement).Object,
                authenticatorAttachment: AuthenticatorAttachment.Platform));

        Assert.Equal(Fido2ErrorCode.AttachmentNotDeclaredInMetadata, ex.Code);
    }

    [Fact]
    public async Task ACrossPlatformAttachmentIsRejectedAtStrictWhenMetadataDeclaresOnlyInternalAsync()
    {
        var statement = new MetadataStatement { AuthenticatorGetInfo = new AuthenticatorGetInfo { Transports = ["internal"] } };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                null,
                config: Config(MetadataConsistencyStrictness.Strict),
                storedAaGuid: Aaguid,
                metadataService: MockMetadataService(statement).Object,
                authenticatorAttachment: AuthenticatorAttachment.CrossPlatform));

        Assert.Equal(Fido2ErrorCode.AttachmentNotDeclaredInMetadata, ex.Code);
    }

    [Fact]
    public async Task APlatformAttachmentIsOnlyLoggedAtStandardWhenMismatchedAsync()
    {
        var statement = new MetadataStatement { AuthenticatorGetInfo = new AuthenticatorGetInfo { Transports = ["usb"] } };
        var logger = new ListLogger<Fido2>();

        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(MetadataConsistencyStrictness.Standard),
            storedAaGuid: Aaguid,
            metadataService: MockMetadataService(statement).Object,
            authenticatorAttachment: AuthenticatorAttachment.Platform,
            logger: logger);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
        Assert.Single(logger.WithEventId(1206));
        Assert.Empty(logger.WithEventId(1207));
    }

    [Fact]
    public async Task APlatformAttachmentIsAcceptedAtStrictWhenMetadataDeclaresInternalAsync()
    {
        var statement = new MetadataStatement { AuthenticatorGetInfo = new AuthenticatorGetInfo { Transports = ["internal"] } };

        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(MetadataConsistencyStrictness.Strict),
            storedAaGuid: Aaguid,
            metadataService: MockMetadataService(statement).Object,
            authenticatorAttachment: AuthenticatorAttachment.Platform);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task NoAttachmentReportedIsAcceptedAtStrictEvenWithANarrowMetadataStatementAsync()
    {
        // The client reported no attachment at all -- nothing to compare, not a claim either way.
        var statement = new MetadataStatement { AuthenticatorGetInfo = new AuthenticatorGetInfo { Transports = ["internal"] } };

        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(MetadataConsistencyStrictness.Strict),
            storedAaGuid: Aaguid,
            metadataService: MockMetadataService(statement).Object,
            authenticatorAttachment: null);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    #endregion

    #region Extensions (weak tier)

    [Fact]
    public async Task AnUndeclaredExtensionAtAssertionIsRejectedAtStrictAsync()
    {
        var statement = new MetadataStatement { AuthenticatorGetInfo = new AuthenticatorGetInfo { Extensions = ["credBlob"] } };
        var clientExtensionResults = new AuthenticationExtensionsClientOutputs { PRF = new AuthenticationExtensionsPRFOutputs() };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                null,
                clientExtensionResults: clientExtensionResults,
                config: Config(MetadataConsistencyStrictness.Strict),
                storedAaGuid: Aaguid,
                metadataService: MockMetadataService(statement).Object));

        Assert.Equal(Fido2ErrorCode.ExtensionNotDeclaredInMetadata, ex.Code);
    }

    [Fact]
    public async Task ADeclaredExtensionAtAssertionIsAcceptedAtStrictAsync()
    {
        var statement = new MetadataStatement { AuthenticatorGetInfo = new AuthenticatorGetInfo { Extensions = ["hmac-secret"] } };
        var clientExtensionResults = new AuthenticationExtensionsClientOutputs { PRF = new AuthenticationExtensionsPRFOutputs() };

        var result = await L3AssertionHarness.AssertAsync(
            null,
            clientExtensionResults: clientExtensionResults,
            config: Config(MetadataConsistencyStrictness.Strict),
            storedAaGuid: Aaguid,
            metadataService: MockMetadataService(statement).Object);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task ADeclaredExtensionViaSupportedExtensionsAtAssertionIsAcceptedAtStrictAsync()
    {
        // Same as above, but declared via the statement's supportedExtensions rather than
        // authenticatorGetInfo.extensions -- the two are unioned, and this exercises the other half.
        var statement = new MetadataStatement
        {
            AuthenticatorGetInfo = new AuthenticatorGetInfo(),
            SupportedExtensions = [new ExtensionDescriptor { Id = "credBlob" }]
        };
        var clientExtensionResults = new AuthenticationExtensionsClientOutputs { CredBlob = true };

        var result = await L3AssertionHarness.AssertAsync(
            null,
            clientExtensionResults: clientExtensionResults,
            config: Config(MetadataConsistencyStrictness.Strict),
            storedAaGuid: Aaguid,
            metadataService: MockMetadataService(statement).Object);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    #endregion

    #region Gating

    [Fact]
    public async Task EveryCheckIsSkippedWithoutAStoredAaguidEvenAtStrictAsync()
    {
        var statement = new MetadataStatement
        {
            MultiDeviceCredentialSupport = "unsupported",
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Transports = ["internal"] }
        };

        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(MetadataConsistencyStrictness.Strict),
            storedAaGuid: null,
            metadataService: MockMetadataService(statement).Object,
            authenticatorAttachment: AuthenticatorAttachment.CrossPlatform,
            flags: AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE | AuthenticatorFlags.BS);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task EveryCheckIsSkippedWhenStrictnessIsOffAsync()
    {
        var statement = new MetadataStatement
        {
            MultiDeviceCredentialSupport = "unsupported",
            AuthenticatorGetInfo = new AuthenticatorGetInfo { Transports = ["internal"] }
        };
        var logger = new ListLogger<Fido2>();

        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(MetadataConsistencyStrictness.Off),
            storedAaGuid: Aaguid,
            metadataService: MockMetadataService(statement).Object,
            authenticatorAttachment: AuthenticatorAttachment.CrossPlatform,
            flags: AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE | AuthenticatorFlags.BS,
            logger: logger);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
        Assert.Empty(logger.WithEventId(1206));
    }

    #endregion
}
