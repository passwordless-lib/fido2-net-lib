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
/// Covers <see cref="Fido2Configuration.RecheckMetadataStatusOnAssertion"/>: whether an authenticator model
/// revoked in MDS after a credential was registered is caught at the credential's next sign-in.
/// </summary>
public class AssertionMetadataStatusRecheckTests
{
    private static Mock<IMetadataService> MockMetadataService(AuthenticatorStatus status)
    {
        var metadataService = new Mock<IMetadataService>();
        metadataService
            .Setup(m => m.GetEntryAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MetadataBLOBPayloadEntry
            {
                StatusReports = [new StatusReport { Status = status }]
            });
        return metadataService;
    }

    private static Fido2Configuration Config(bool recheck) => new()
    {
        RPID = L3AssertionHarness.Rp,
        RPName = L3AssertionHarness.Rp,
        Origins = new HashSet<string> { L3AssertionHarness.Rp },
        RecheckMetadataStatusOnAssertion = recheck
    };

    [Fact]
    public async Task AnAssertionIsRejectedWhenTheStoredAaguidsStatusIsUndesiredAndRecheckIsEnabledAsync()
    {
        var ex = await Assert.ThrowsAsync<UndesiredMetadataStatusFido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                null,
                config: Config(recheck: true),
                storedAaGuid: Guid.NewGuid(),
                metadataService: MockMetadataService(AuthenticatorStatus.REVOKED).Object));

        Assert.Equal(AuthenticatorStatus.REVOKED, ex.StatusReport.Status);
    }

    [Fact]
    public async Task AnAssertionSucceedsWhenRecheckIsDisabledEvenIfTheStatusIsUndesiredAsync()
    {
        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(recheck: false),
            storedAaGuid: Guid.NewGuid(),
            metadataService: MockMetadataService(AuthenticatorStatus.REVOKED).Object);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task AnAssertionSucceedsWhenRecheckIsEnabledButNoStoredAaguidIsSuppliedAsync()
    {
        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(recheck: true),
            metadataService: MockMetadataService(AuthenticatorStatus.REVOKED).Object);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task AnAssertionSucceedsWhenRecheckIsEnabledAndTheStatusIsNotUndesiredAsync()
    {
        var result = await L3AssertionHarness.AssertAsync(
            null,
            config: Config(recheck: true),
            storedAaGuid: Guid.NewGuid(),
            metadataService: MockMetadataService(AuthenticatorStatus.FIDO_CERTIFIED).Object);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }
}
