using System.Security.Cryptography;

using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class CtapMakeCredentialExtensionsTests
{
    [Fact]
    public void GetPayload_WithoutExtensions_OmitsMember()
    {
        var command = new AuthenticatorMakeCredentialCommand(
            clientDataHash: new byte[32],
            rpEntity: new PublicKeyCredentialRpEntity("example.com", "Acme", null),
            user: new PublicKeyCredentialUserEntity { Id = [1, 2, 3], Name = "user" },
            pubKeyCredParams: [new PubKeyCredParam(COSE.Algorithm.ES256)],
            options: new AuthenticatorMakeCredentialOptions());

        var map = (CborMap)CborObject.Decode(command.GetPayload().AsMemory(1));

        Assert.DoesNotContain(map, kvp => (int)kvp.Key == 0x06);
    }

    [Fact]
    public void GetPayload_WithCredProtectAndHmacSecret_EncodesBothEntries()
    {
        var command = new AuthenticatorMakeCredentialCommand(
            clientDataHash: new byte[32],
            rpEntity: new PublicKeyCredentialRpEntity("example.com", "Acme", null),
            user: new PublicKeyCredentialUserEntity { Id = [1, 2, 3], Name = "user" },
            pubKeyCredParams: [new PubKeyCredParam(COSE.Algorithm.ES256)],
            options: new AuthenticatorMakeCredentialOptions(),
            extensions: new CtapMakeCredentialExtensions
            {
                CredProtect = CredentialProtectionPolicy.UserVerificationRequired,
                HmacSecret = true,
                CredBlob = [1, 2, 3, 4],
            });

        var map = (CborMap)CborObject.Decode(command.GetPayload().AsMemory(1));

        var extensions = (CborMap)map.Single(kvp => (int)kvp.Key == 0x06).Value;

        Assert.Equal(3, (int)extensions["credProtect"]!);
        Assert.True((bool)extensions["hmac-secret"]!);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, (byte[])extensions["credBlob"]!);
    }

    [Fact]
    public void GetPayload_WithHmacSecretMc_EncodesKeyAgreementSaltEncSaltAuth()
    {
        using var authenticatorEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authenticatorKey = new CredentialPublicKey(authenticatorEcdsa, COSE.Algorithm.ES256);

        var sharedSecret = PinUvAuthProtocolOne.Instance.GenerateSharedSecret(authenticatorKey, out var platformKey);
        var salt1 = RandomNumberGenerator.GetBytes(32);

        var hmacSecretMc = HmacSecretInput.Create(platformKey, sharedSecret, salt1);

        var command = new AuthenticatorMakeCredentialCommand(
            clientDataHash: new byte[32],
            rpEntity: new PublicKeyCredentialRpEntity("example.com", "Acme", null),
            user: new PublicKeyCredentialUserEntity { Id = [1, 2, 3], Name = "user" },
            pubKeyCredParams: [new PubKeyCredParam(COSE.Algorithm.ES256)],
            options: new AuthenticatorMakeCredentialOptions(),
            extensions: new CtapMakeCredentialExtensions
            {
                HmacSecret = true,
                HmacSecretMc = hmacSecretMc,
            });

        var map = (CborMap)CborObject.Decode(command.GetPayload().AsMemory(1));
        var extensions = (CborMap)map.Single(kvp => (int)kvp.Key == 0x06).Value;
        var hmacSecretMcMap = (CborMap)extensions["hmac-secret-mc"]!;

        Assert.Equal(hmacSecretMc.SaltEnc, (byte[])hmacSecretMcMap.Single(kvp => (int)kvp.Key == 0x02).Value);
        Assert.Equal(hmacSecretMc.SaltAuth, (byte[])hmacSecretMcMap.Single(kvp => (int)kvp.Key == 0x03).Value);
    }

    [Fact]
    public void GetPayload_WithAdditionalExtensions_MergesEntries()
    {
        var command = new AuthenticatorMakeCredentialCommand(
            clientDataHash: new byte[32],
            rpEntity: new PublicKeyCredentialRpEntity("example.com", "Acme", null),
            user: new PublicKeyCredentialUserEntity { Id = [1, 2, 3], Name = "user" },
            pubKeyCredParams: [new PubKeyCredParam(COSE.Algorithm.ES256)],
            options: new AuthenticatorMakeCredentialOptions(),
            extensions: new CtapMakeCredentialExtensions
            {
                LargeBlobKey = true,
                AdditionalExtensions = new CborMap { { "vendorExt", true } },
            });

        var map = (CborMap)CborObject.Decode(command.GetPayload().AsMemory(1));
        var extensions = (CborMap)map.Single(kvp => (int)kvp.Key == 0x06).Value;

        Assert.True((bool)extensions["largeBlobKey"]!);
        Assert.True((bool)extensions["vendorExt"]!);
    }
}
