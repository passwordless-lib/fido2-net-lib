using System;
using System.Collections.Generic;
using System.Threading;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Extensions.Logging;

using Moq;

namespace Test;

/// <summary>
/// Covers the optional <see cref="ILogger{TCategoryName}"/> on <see cref="Fido2"/>: every ceremony outcome is logged
/// with a stable event ID (1200-1205) and enough context to act on, and logging is entirely opt-in -- no logger
/// supplied must behave exactly as before.
/// </summary>
public class LoggingTests
{
    private static Fido2Configuration Config(Action<Fido2Configuration> configure = null)
    {
        var config = new Fido2Configuration
        {
            RPID = L3AssertionHarness.Rp,
            RPName = L3AssertionHarness.Rp,
            Origins = new HashSet<string> { L3AssertionHarness.Rp },
        };
        configure?.Invoke(config);
        return config;
    }

    [Fact]
    public async Task ASuccessfulAssertionIsLoggedWithItsOutcomeAsync()
    {
        var logger = new ListLogger<Fido2>();

        await L3AssertionHarness.AssertAsync(null, logger: logger);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(1202, entry.EventId.Id);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Contains("8dA", entry.Message);
        Assert.Contains(L3AssertionHarness.Rp, entry.Message);
        Assert.Contains("sign count 1", entry.Message);
    }

    [Fact]
    public async Task ARejectedAssertionIsLoggedAsAWarningWithItsErrorCodeAsync()
    {
        var logger = new ListLogger<Fido2>();
        var deniedAaguid = Guid.NewGuid();

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                null,
                config: Config(c => c.AaguidDenyList = [deniedAaguid]),
                storedAaGuid: deniedAaguid,
                logger: logger));

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(1203, entry.EventId.Id);
        Assert.Equal(LogLevel.Warning, entry.Level);
        // A rejection is routine and attacker-triggerable: the code and reason, not a stack trace.
        Assert.Null(entry.Exception);
        Assert.Contains(nameof(Fido2ErrorCode.AaguidDenied), entry.Message);
        Assert.Contains(ex.Message, entry.Message);
        Assert.Contains("8dA", entry.Message);
    }

    [Fact]
    public async Task AnUnexpectedFailureIsLoggedAsAnErrorWithTheExceptionAsync()
    {
        var logger = new ListLogger<Fido2>();
        var failure = new InvalidOperationException("the credential store is down");

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => L3AssertionHarness.AssertAsync(null, logger: logger, isUserHandleOwnerOfCredentialId: (_, _) => throw failure));

        Assert.Same(failure, thrown);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(1205, entry.EventId.Id);
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Same(failure, entry.Exception);
        Assert.Contains("authentication", entry.Message);
    }

    [Fact]
    public async Task ACancelledCeremonyIsNotLoggedAsync()
    {
        var logger = new ListLogger<Fido2>();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => L3AssertionHarness.AssertAsync(null, logger: logger, isUserHandleOwnerOfCredentialId: (_, _) => throw new OperationCanceledException()));

        Assert.Empty(logger.Entries);
    }

    [Fact]
    public async Task EnablingTheMetadataRecheckWithoutAStoredAaguidIsReportedAsync()
    {
        var logger = new ListLogger<Fido2>();
        var metadataService = new Mock<IMetadataService>();

        await L3AssertionHarness.AssertAsync(
            null,
            config: Config(c => c.RecheckMetadataStatusOnAssertion = true),
            metadataService: metadataService.Object,
            logger: logger);

        var warning = Assert.Single(logger.WithEventId(1204));
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.Contains("8dA", warning.Message);
        Assert.Single(logger.WithEventId(1202));
    }

    [Fact]
    public async Task TheRecheckWarningIsNotLoggedWhenTheAaguidIsSuppliedAsync()
    {
        var logger = new ListLogger<Fido2>();

        await L3AssertionHarness.AssertAsync(
            null,
            config: Config(c => c.RecheckMetadataStatusOnAssertion = true),
            metadataService: new Mock<IMetadataService>().Object,
            storedAaGuid: Guid.NewGuid(),
            logger: logger);

        Assert.Empty(logger.WithEventId(1204));
    }

    [Fact]
    public async Task AnAttackerSuppliedCredentialIdIsLoggedTruncatedAsync()
    {
        var logger = new ListLogger<Fido2>();
        var rawId = new byte[600];

        await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(null, rawId: rawId, logger: logger));

        var entry = Assert.Single(logger.WithEventId(1203));
        Assert.Contains(new string('A', 64) + "...", entry.Message);
        Assert.DoesNotContain(new string('A', 65), entry.Message);
    }

    [Fact]
    public async Task AMissingResponseIsLoggedWithoutACredentialIdAsync()
    {
        var logger = new ListLogger<Fido2>();
        var lib = new Fido2(Config(), metadataService: null, logger);

        await Assert.ThrowsAnyAsync<Exception>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = null,
            OriginalOptions = new AssertionOptions(),
            StoredPublicKey = [],
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = (_, _) => System.Threading.Tasks.Task.FromResult(true)
        }));

        Assert.Contains("(none)", Assert.Single(logger.Entries).Message);
    }

    [Fact]
    public async Task NoLoggerSuppliedBehavesExactlyAsBeforeAsync()
    {
        var result = await L3AssertionHarness.AssertAsync(null);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public void TheTwoArgumentConstructorIsKept()
    {
        // Binary compatibility: code compiled against Fido2(config, metadataService) must still find it.
        Assert.NotNull(typeof(Fido2).GetConstructor([typeof(Fido2Configuration), typeof(IMetadataService)]));
    }

    public class Registration : Fido2Tests.Attestation
    {
        public Registration()
        {
            _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborMap() } };
            _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
        }

        [Fact]
        public async Task ASuccessfulRegistrationIsLoggedWithTheAuthenticatorModelAsync()
        {
            var logger = new ListLogger<Fido2>();

            await MakeAttestationResponseAsync(null, logger: logger);

            var entry = Assert.Single(logger.Entries);
            Assert.Equal(1200, entry.EventId.Id);
            Assert.Equal(LogLevel.Information, entry.Level);
            Assert.Contains(_aaguid.ToString(), entry.Message);
            Assert.Contains("attestation format none", entry.Message);
            Assert.Contains(System.Buffers.Text.Base64Url.EncodeToString(_credentialID), entry.Message);
        }

        [Fact]
        public async Task ARejectedRegistrationIsLoggedAsAWarningAsync()
        {
            var logger = new ListLogger<Fido2>();

            await Assert.ThrowsAsync<Fido2VerificationException>(
                () => MakeAttestationResponseAsync(null, configure: c => c.AaguidDenyList = [_aaguid], logger: logger));

            var entry = Assert.Single(logger.Entries);
            Assert.Equal(1201, entry.EventId.Id);
            Assert.Equal(LogLevel.Warning, entry.Level);
            Assert.Null(entry.Exception);
            Assert.Contains(nameof(Fido2ErrorCode.AaguidDenied), entry.Message);
        }

        [Fact]
        public async Task AMissingRegistrationResponseIsLoggedWithoutACredentialIdAsync()
        {
            var logger = new ListLogger<Fido2>();
            var lib = new Fido2(new Fido2Configuration { RPID = "localhost" }, metadataService: null, logger);

            await Assert.ThrowsAnyAsync<Exception>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = null,
                OriginalOptions = new CredentialCreateOptions
                {
                    Rp = new PublicKeyCredentialRpEntity("localhost", "localhost"),
                    User = new Fido2User { Id = [1], Name = "u", DisplayName = "u" },
                    Challenge = [1],
                    PubKeyCredParams = []
                },
                IsCredentialIdUniqueToUserCallback = (_, _) => System.Threading.Tasks.Task.FromResult(true)
            }));

            Assert.Contains("(none)", Assert.Single(logger.Entries).Message);
        }

        [Fact]
        public async Task AnUnexpectedRegistrationFailureIsLoggedAsAnErrorAsync()
        {
            var logger = new ListLogger<Fido2>();
            var failure = new InvalidOperationException("metadata lookup blew up");
            var metadataService = new Mock<IMetadataService>();
            metadataService.Setup(m => m.GetEntryAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>())).ThrowsAsync(failure);

            await Assert.ThrowsAsync<InvalidOperationException>(() => MakeAttestationResponseAsync(null, metadataService: metadataService.Object, logger: logger));

            var entry = Assert.Single(logger.Entries);
            Assert.Equal(1205, entry.EventId.Id);
            Assert.Same(failure, entry.Exception);
            Assert.Contains("registration", entry.Message);
        }
    }
}
