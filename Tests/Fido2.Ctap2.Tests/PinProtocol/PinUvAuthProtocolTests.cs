using System.Linq;
using System.Security.Cryptography;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class PinUvAuthProtocolTests
{
    [Fact]
    public void Select_ReturnsExpectedSingletons()
    {
        Assert.Same(PinUvAuthProtocolOne.Instance, PinUvAuthProtocol.Select(1));
        Assert.Same(PinUvAuthProtocolTwo.Instance, PinUvAuthProtocol.Select(2));
    }

    [Fact]
    public void Select_UnsupportedVersion_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PinUvAuthProtocol.Select(3));
    }

    [Fact]
    public void ProtocolOne_Authenticate_ReturnsFirst16BytesOfHmac()
    {
        var protocol = PinUvAuthProtocolOne.Instance;
        var key = RandomNumberGenerator.GetBytes(32);
        byte[] message = "hello"u8.ToArray();

        var signature = protocol.Authenticate(key, message);

        Assert.Equal(16, signature.Length);
        Assert.Equal(HMACSHA256.HashData(key, message).AsSpan(0, 16).ToArray(), signature);
    }

    [Fact]
    public void ProtocolOne_VerifyRoundTrips()
    {
        var protocol = PinUvAuthProtocolOne.Instance;
        var key = RandomNumberGenerator.GetBytes(32);
        byte[] message = "hello"u8.ToArray();

        var signature = protocol.Authenticate(key, message);

        Assert.True(protocol.Verify(key, message, signature));
        Assert.False(protocol.Verify(key, "different"u8, signature));
    }

    [Fact]
    public void ProtocolOne_EncryptDecrypt_RoundTrips()
    {
        var protocol = PinUvAuthProtocolOne.Instance;
        var key = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = new byte[64]; // must be a multiple of the AES block size
        RandomNumberGenerator.Fill(plaintext);

        var ciphertext = protocol.Encrypt(key, plaintext);
        var decrypted = protocol.Decrypt(key, ciphertext);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void ProtocolTwo_Authenticate_ReturnsFull32ByteHmac_UsingFirst32BytesOfKey()
    {
        var protocol = PinUvAuthProtocolTwo.Instance;
        var sharedSecret = RandomNumberGenerator.GetBytes(64); // 32-byte HMAC key || 32-byte AES key
        byte[] message = "hello"u8.ToArray();

        var signature = protocol.Authenticate(sharedSecret, message);

        Assert.Equal(32, signature.Length);
        Assert.Equal(HMACSHA256.HashData(sharedSecret[..32], message), signature);
    }

    [Fact]
    public void ProtocolTwo_Authenticate_WithBarePinUvAuthToken_UsesEntireKey()
    {
        var protocol = PinUvAuthProtocolTwo.Instance;
        var pinUvAuthToken = RandomNumberGenerator.GetBytes(32); // protocol two tokens are exactly 32 bytes
        byte[] message = "hello"u8.ToArray();

        var signature = protocol.Authenticate(pinUvAuthToken, message);

        Assert.Equal(HMACSHA256.HashData(pinUvAuthToken, message), signature);
    }

    [Fact]
    public void ProtocolTwo_VerifyRoundTrips()
    {
        var protocol = PinUvAuthProtocolTwo.Instance;
        var sharedSecret = RandomNumberGenerator.GetBytes(64);
        byte[] message = "hello"u8.ToArray();

        var signature = protocol.Authenticate(sharedSecret, message);

        Assert.True(protocol.Verify(sharedSecret, message, signature));
        Assert.False(protocol.Verify(sharedSecret, "different"u8, signature));
    }

    [Fact]
    public void ProtocolTwo_Verify_RejectsProtocolOneLengthSignature()
    {
        var protocol = PinUvAuthProtocolTwo.Instance;
        var sharedSecret = RandomNumberGenerator.GetBytes(64);

        Assert.False(protocol.Verify(sharedSecret, "hello"u8, new byte[16]));
    }

    [Fact]
    public void ProtocolTwo_EncryptDecrypt_RoundTrips_UsingAesKeyPortionOnly()
    {
        var protocol = PinUvAuthProtocolTwo.Instance;
        var sharedSecret = RandomNumberGenerator.GetBytes(64);
        byte[] plaintext = new byte[64];
        RandomNumberGenerator.Fill(plaintext);

        var ciphertext = protocol.Encrypt(sharedSecret, plaintext);
        var decrypted = protocol.Decrypt(sharedSecret, ciphertext);

        Assert.Equal(plaintext, decrypted);
        // iv (16) + ciphertext (64), unlike protocol one which has no IV overhead
        Assert.Equal(16 + plaintext.Length, ciphertext.Length);
    }

    [Fact]
    public void ProtocolTwo_Encrypt_UsesRandomIv_ProducingDifferentCiphertextEachTime()
    {
        var protocol = PinUvAuthProtocolTwo.Instance;
        var sharedSecret = RandomNumberGenerator.GetBytes(64);
        byte[] plaintext = new byte[16];

        var ciphertext1 = protocol.Encrypt(sharedSecret, plaintext);
        var ciphertext2 = protocol.Encrypt(sharedSecret, plaintext);

        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void ProtocolTwo_Decrypt_TooShort_Throws()
    {
        var protocol = PinUvAuthProtocolTwo.Instance;
        var sharedSecret = RandomNumberGenerator.GetBytes(64);

        Assert.Throws<CryptographicException>(() => protocol.Decrypt(sharedSecret, new byte[8]));
    }

    [Fact]
    public void ProtocolTwo_GenerateSharedSecret_MatchesIndependentEcdhPlusHkdfDerivation()
    {
        using var authenticatorEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authenticatorPublicKey = new CredentialPublicKey(authenticatorEcdsa, COSE.Algorithm.ES256);

        var platformSharedSecret = PinUvAuthProtocolTwo.Instance.GenerateSharedSecret(authenticatorPublicKey, out var platformPublicKey);

        // Independently derive Z from the authenticator's side using its private key and the
        // platform's returned public key, then apply protocol two's kdf, and confirm both sides agree.
        using var platformEcdsaPublic = platformPublicKey.CreateECDsa();
        using var authenticatorEcdh = ECDiffieHellman.Create(authenticatorEcdsa.ExportParameters(true));
        using var platformEcdh = ECDiffieHellman.Create(platformEcdsaPublic.ExportParameters(false));

        byte[] z = authenticatorEcdh.DeriveRawSecretAgreement(platformEcdh.PublicKey);

        byte[] zeroSalt = new byte[32];
        byte[] hmacKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, zeroSalt, "CTAP2 HMAC key"u8.ToArray());
        byte[] aesKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, zeroSalt, "CTAP2 AES key"u8.ToArray());
        byte[] expectedSharedSecret = [.. hmacKey, .. aesKey];

        Assert.Equal(expectedSharedSecret, platformSharedSecret);
        Assert.Equal(64, platformSharedSecret.Length);
    }

    [Fact]
    public void ProtocolTwo_Authenticate_MatchesKnownAnswerHmacSha256Vector()
    {
        // Independent known-answer vector (computed via `openssl dgst -sha256 -mac hmac`, not this
        // codebase), for HMAC-SHA256 with a 32-byte all-0x0b key and message "Hi There":
        // openssl dgst -sha256 -mac hmac -macopt hexkey:0b0b...0b (32 bytes) <<< "Hi There"
        //   => 198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7
        byte[] hmacKey = Enumerable.Repeat((byte)0x0b, 32).ToArray();
        byte[] aesKeyPortion = new byte[32]; // unused by Authenticate; present only because a real
                                             // protocol two shared secret is 64 bytes (hmacKey || aesKey)
        byte[] sharedSecret = [.. hmacKey, .. aesKeyPortion];
        byte[] message = "Hi There"u8.ToArray();
        byte[] expected = Convert.FromHexString("198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7");

        var signature = PinUvAuthProtocolTwo.Instance.Authenticate(sharedSecret, message);

        Assert.Equal(expected, signature);
    }

    [Fact]
    public void ProtocolTwo_Decrypt_MatchesKnownAnswerAes256CbcVector()
    {
        // Independent known-answer vector (computed via `openssl enc -aes-256-cbc -nopad`, not this
        // codebase): key = bytes 0x00..0x1f, iv = bytes 0x00..0x0f, a 32-byte deterministic
        // plaintext, encrypted with AES-256-CBC/no-padding to produce the expected ciphertext below.
        byte[] aesKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] hmacKeyPortion = new byte[32]; // unused by Decrypt
        byte[] sharedSecret = [.. hmacKeyPortion, .. aesKey];
        byte[] iv = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        byte[] expectedPlaintext = Enumerable.Range(0, 32).Select(i => (byte)((i * 7 + 3) % 256)).ToArray();
        byte[] knownCiphertext = Convert.FromHexString("61566a8c558954b3685aebb31fdeff58e15d4fe6d2312c7356fb737472bff0f3");

        byte[] demCiphertext = [.. iv, .. knownCiphertext];

        var decrypted = PinUvAuthProtocolTwo.Instance.Decrypt(sharedSecret, demCiphertext);

        Assert.Equal(expectedPlaintext, decrypted);
    }

    [Fact]
    public void ProtocolOne_GenerateSharedSecret_MatchesIndependentEcdhPlusSha256Derivation()
    {
        using var authenticatorEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authenticatorPublicKey = new CredentialPublicKey(authenticatorEcdsa, COSE.Algorithm.ES256);

        var platformSharedSecret = PinUvAuthProtocolOne.Instance.GenerateSharedSecret(authenticatorPublicKey, out var platformPublicKey);

        using var platformEcdsaPublic = platformPublicKey.CreateECDsa();
        using var authenticatorEcdh = ECDiffieHellman.Create(authenticatorEcdsa.ExportParameters(true));
        using var platformEcdh = ECDiffieHellman.Create(platformEcdsaPublic.ExportParameters(false));

        byte[] z = authenticatorEcdh.DeriveRawSecretAgreement(platformEcdh.PublicKey);
        byte[] expectedSharedSecret = SHA256.HashData(z);

        Assert.Equal(expectedSharedSecret, platformSharedSecret);
        Assert.Equal(32, platformSharedSecret.Length);
    }
}
