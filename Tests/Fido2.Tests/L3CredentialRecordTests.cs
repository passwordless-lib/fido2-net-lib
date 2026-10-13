using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Fido2NetLib.Serialization;

namespace Test;

/// <summary>
/// Covers the WebAuthn Level 3 BE/BS flag invariant that applies to the registration ceremony
/// (§7.1 step 15) and the authentication ceremony (§7.2 step 21): if the BE bit is not set, the
/// BS bit must not be set either. This is the only L3 credential-record rule backported to the
/// 4.x line; the comparison of the current BE flag against the value recorded at registration
/// (§7.2 step 22) and the <c>uvInitialized</c> state update (§7.2 step 28) are later L3 additions
/// not included here.
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

    private static (CredentialCreateOptions Options, AuthenticatorAttestationRawResponse Response) MakeRegistration(AuthenticatorFlags flags)
    {
        var challenge = RandomNumberGenerator.GetBytes(128);

        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(
            new AuthenticatorResponse(type: "webauthn.create", challenge: challenge, origin: Rp),
            FidoSerializerContext.Default.AuthenticatorResponse);

        // No AT flag / attested credential data: the BE/BS invariant (step 15) is checked before the
        // HasAttestedCredentialData check (step 17), so a minimal, attestation-data-free authData reaches it.
        var authData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(Rp)), flags, 0, null).ToByteArray();

        var attestationObject = new CborMap
        {
            { "fmt", "none" },
            { "attStmt", new CborMap() },
            { "authData", authData }
        }.Encode();

        var options = new CredentialCreateOptions
        {
            Challenge = challenge,
            PubKeyCredParams = [new PubKeyCredParam(COSE.Algorithm.ES256)],
            Rp = new PublicKeyCredentialRpEntity(Rp, Rp, ""),
            User = new Fido2User { Name = "testuser", Id = "testuser"u8.ToArray(), DisplayName = "Test User" },
        };

        var response = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = attestationObject,
                ClientDataJson = clientDataJson,
            },
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
        byte[] storedPublicKey = null)
    {
        return lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = storedPublicKey,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = static (args, cancellationToken) => Task.FromResult(true)
        });
    }

    private static Task<RegisteredPublicKeyCredential> RegisterAsync(Fido2 lib, CredentialCreateOptions options, AuthenticatorAttestationRawResponse response)
    {
        return lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = response,
            OriginalOptions = options,
            IsCredentialIdUniqueToUserCallback = static (args, cancellationToken) => Task.FromResult(true)
        });
    }

    [Fact]
    public async Task RegistrationWithBackupStateButNotBackupEligibleIsRejectedAsync()
    {
        // Same invariant as the assertion-side check below, enforced at registration too: a credential
        // can already be backed up (BS set) at creation, e.g. a synced passkey, so the check can't wait
        // until the first assertion.
        var (options, response) = MakeRegistration(AuthenticatorFlags.UP | AuthenticatorFlags.BS);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => RegisterAsync(MakeLib(), options, response));

        Assert.Equal(Fido2ErrorCode.InvalidBackupFlags, ex.Code);
        Assert.Equal(Fido2ErrorMessages.InvalidBackupFlags, ex.Message);
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

}
