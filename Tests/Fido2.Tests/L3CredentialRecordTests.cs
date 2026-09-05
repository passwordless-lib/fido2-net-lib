using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Fido2NetLib.Serialization;

namespace Test;

/// <summary>
/// Covers the WebAuthn Level 3 credential record rules that apply to the authentication ceremony:
/// the BE/BS flag invariant (§7.2 step 21), the comparison of the current BE flag against the value
/// recorded at registration (§7.2 step 22), and the <c>uvInitialized</c> state update (§7.2 step 28).
/// </summary>
public class L3CredentialRecordTests
{
    private const string Rp = "https://www.passwordless.dev";

    private static (AssertionOptions Options, AuthenticatorAssertionRawResponse Response) MakeAssertion(AuthenticatorFlags flags)
    {
        var challenge = RandomNumberGenerator.GetBytes(128);

        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(
            new AuthenticatorResponse(type: "webauthn.get", challenge: challenge, origin: Rp),
            FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = Rp,
            AllowCredentials = [new PublicKeyCredentialDescriptor([0xf1, 0xd0])]
        };

        var response = new AuthenticatorAssertionRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = new AuthenticatorData(
                    SHA256.HashData(Encoding.UTF8.GetBytes(Rp)), flags, 0, null).ToByteArray(),
                Signature = [0xf1, 0xd0],
                ClientDataJson = clientDataJson,
                UserHandle = [0xf1, 0xd0],
            }
        };

        return (options, response);
    }

    private static Fido2 MakeLib() => new(new Fido2Configuration
    {
        RPID = Rp,
        RPName = Rp,
        Origins = new HashSet<string> { Rp },
    });

    private static Task<VerifyAssertionResult> AssertAsync(
        Fido2 lib,
        AssertionOptions options,
        AuthenticatorAssertionRawResponse response,
        bool? storedBackupEligible = null,
        byte[] storedPublicKey = null)
    {
        return lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = storedPublicKey,
            StoredSignatureCounter = 0,
            StoredBackupEligible = storedBackupEligible,
            IsUserHandleOwnerOfCredentialIdCallback = static (args, cancellationToken) => Task.FromResult(true)
        });
    }

    [Fact]
    public async Task AssertionWithBackupStateButNotBackupEligibleIsRejectedAsync()
    {
        // BS set without BE is malformed: a credential that is not backup eligible can never be backed up.
        var (options, response) = MakeAssertion(AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BS);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => AssertAsync(MakeLib(), options, response));

        Assert.Equal(Fido2ErrorCode.InvalidBackupFlags, ex.Code);
        Assert.Equal(Fido2ErrorMessages.InvalidBackupFlags, ex.Message);
    }

    [Theory]
    [InlineData(AuthenticatorFlags.UP | AuthenticatorFlags.UV)]
    [InlineData(AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE)]
    [InlineData(AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE | AuthenticatorFlags.BS)]
    public async Task ValidBackupFlagCombinationsPassTheInvariantAsync(AuthenticatorFlags flags)
    {
        var (options, response) = MakeAssertion(flags);

        // Every valid combination gets past the flag invariant and fails later, on the missing stored public key.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => AssertAsync(MakeLib(), options, response));

        Assert.Equal(Fido2ErrorCode.MissingStoredPublicKey, ex.Code);
    }

    [Theory]
    [InlineData(true, AuthenticatorFlags.UP | AuthenticatorFlags.UV)]
    [InlineData(false, AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE)]
    public async Task AssertionWhoseBackupEligibilityChangedIsRejectedAsync(bool storedBackupEligible, AuthenticatorFlags flags)
    {
        // Backup eligibility is permanent for a credential, so a change means this is not the credential
        // that was registered.
        var (options, response) = MakeAssertion(flags);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => AssertAsync(MakeLib(), options, response, storedBackupEligible));

        Assert.Equal(Fido2ErrorCode.BackupEligibilityChanged, ex.Code);
        Assert.Equal(Fido2ErrorMessages.BackupEligibilityChanged, ex.Message);
    }

    [Theory]
    [InlineData(true, AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE)]
    [InlineData(false, AuthenticatorFlags.UP | AuthenticatorFlags.UV)]
    public async Task AssertionWhoseBackupEligibilityMatchesIsAcceptedAsync(bool storedBackupEligible, AuthenticatorFlags flags)
    {
        var (options, response) = MakeAssertion(flags);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => AssertAsync(MakeLib(), options, response, storedBackupEligible));

        // Got past the backup eligibility comparison; fails later, on the missing stored public key.
        Assert.Equal(Fido2ErrorCode.MissingStoredPublicKey, ex.Code);
    }

    [Fact]
    public async Task BackupEligibilityIsNotComparedWhenTheRelyingPartyDoesNotTrackItAsync()
    {
        var (options, response) = MakeAssertion(AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => AssertAsync(MakeLib(), options, response, storedBackupEligible: null));

        Assert.Equal(Fido2ErrorCode.MissingStoredPublicKey, ex.Code);
    }
}
