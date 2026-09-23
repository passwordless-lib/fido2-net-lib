using System.Security.Cryptography;

using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class CtapGetAssertionExtensionsTests
{
    [Fact]
    public void GetPayload_WithoutExtensions_OmitsMember()
    {
        var command = new AuthenticatorGetAssertionCommand("example.com", new byte[32], []);

        var map = (CborMap)CborObject.Decode(command.GetPayload().AsMemory(1));

        Assert.DoesNotContain(map, kvp => (int)kvp.Key == 0x04);
    }

    [Fact]
    public void GetPayload_WithCredBlobAndLargeBlobKey_EncodesBothEntries()
    {
        var command = new AuthenticatorGetAssertionCommand(
            "example.com",
            new byte[32],
            [],
            extensions: new CtapGetAssertionExtensions
            {
                CredBlob = true,
                LargeBlobKey = true,
            });

        var map = (CborMap)CborObject.Decode(command.GetPayload().AsMemory(1));
        var extensions = (CborMap)map.Single(kvp => (int)kvp.Key == 0x04).Value;

        Assert.True((bool)extensions["credBlob"]!);
        Assert.True((bool)extensions["largeBlobKey"]!);
    }

    [Fact]
    public void HmacSecretInput_CreateThenDecryptOutput_RoundTrips()
    {
        using var authenticatorEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authenticatorPublicKey = new CredentialPublicKey(authenticatorEcdsa, COSE.Algorithm.ES256);

        // Platform side: negotiate, then build the hmac-secret input for two salts.
        var sharedSecret = PinUvAuthProtocolOne.Instance.GenerateSharedSecret(authenticatorPublicKey, out var platformKey);
        var salt1 = RandomNumberGenerator.GetBytes(32);
        var salt2 = RandomNumberGenerator.GetBytes(32);

        var hmacSecretInput = HmacSecretInput.Create(platformKey, sharedSecret, salt1, salt2);

        var command = new AuthenticatorGetAssertionCommand(
            "example.com",
            new byte[32],
            [],
            extensions: new CtapGetAssertionExtensions { HmacSecret = hmacSecretInput });

        var map = (CborMap)CborObject.Decode(command.GetPayload().AsMemory(1));
        var extensions = (CborMap)map.Single(kvp => (int)kvp.Key == 0x04).Value;
        var hmacSecretMap = (CborMap)extensions["hmac-secret"]!;

        var saltEnc = (byte[])hmacSecretMap.Single(kvp => (int)kvp.Key == 0x02).Value;
        var saltAuth = (byte[])hmacSecretMap.Single(kvp => (int)kvp.Key == 0x03).Value;

        // Authenticator side: decrypt the salts, verify saltAuth, compute output1/output2 as the
        // spec describes, then encrypt them back — simulating the round trip end to end.
        var decryptedSalts = PinUvAuthProtocolOne.Instance.Decrypt(sharedSecret, saltEnc);
        Assert.True(PinUvAuthProtocolOne.Instance.Verify(sharedSecret, saltEnc, saltAuth));
        Assert.Equal(salt1, decryptedSalts[..32]);
        Assert.Equal(salt2, decryptedSalts[32..]);

        var credRandom = RandomNumberGenerator.GetBytes(32);
        var output1 = HMACSHA256.HashData(credRandom, decryptedSalts[..32]);
        var output2 = HMACSHA256.HashData(credRandom, decryptedSalts[32..]);
        var encryptedOutput = PinUvAuthProtocolOne.Instance.Encrypt(sharedSecret, [.. output1, .. output2]);

        var (decodedOutput1, decodedOutput2) = HmacSecretOutput.Decrypt(sharedSecret, encryptedOutput);

        Assert.Equal(output1, decodedOutput1);
        Assert.Equal(output2, decodedOutput2);
    }
}
