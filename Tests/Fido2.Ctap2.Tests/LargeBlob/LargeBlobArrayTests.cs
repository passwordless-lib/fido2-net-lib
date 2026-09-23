using System.Security.Cryptography;

namespace Fido2NetLib.Ctap2.Tests;

public class LargeBlobArrayTests
{
    [Fact]
    public void InitialSerializedArray_IsEmptyArrayPlusTruncatedHash()
    {
        var initial = LargeBlobArray.InitialSerializedArray;

        Assert.Equal(17, initial.Length);
        Assert.Equal(0x80, initial[0]);
        Assert.Equal(SHA256.HashData([0x80]).AsSpan(0, 16).ToArray(), initial[1..]);
    }

    [Fact]
    public void TryDecode_InitialSerializedArray_YieldsNoEntries()
    {
        var success = LargeBlobArray.TryDecode(LargeBlobArray.InitialSerializedArray, out var entries);

        Assert.True(success);
        Assert.Empty(entries);
    }

    [Fact]
    public void EncodeThenTryDecode_RoundTripsEntries()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var entry = LargeBlobArray.Encrypt(key, "hello large blob"u8);

        var serialized = LargeBlobArray.Encode([entry]);

        var success = LargeBlobArray.TryDecode(serialized, out var entries);

        Assert.True(success);
        var decoded = Assert.Single(entries);

        Assert.Equal(entry.Ciphertext, decoded.Ciphertext);
        Assert.Equal(entry.Nonce, decoded.Nonce);
        Assert.Equal(entry.OrigSize, decoded.OrigSize);
    }

    [Fact]
    public void TryDecode_CorruptedTrailingHash_ReturnsFalse()
    {
        var serialized = LargeBlobArray.Encode([]);
        serialized[^1] ^= 0xFF;

        var success = LargeBlobArray.TryDecode(serialized, out var entries);

        Assert.False(success);
        Assert.Empty(entries);
    }

    [Fact]
    public void TryDecode_TooShort_ReturnsFalse()
    {
        var success = LargeBlobArray.TryDecode([0x01, 0x02], out var entries);

        Assert.False(success);
        Assert.Empty(entries);
    }

    [Fact]
    public void EncryptThenTryDecrypt_RoundTripsPlaintext()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = "the quick brown fox jumps over the lazy dog"u8.ToArray();

        var entry = LargeBlobArray.Encrypt(key, plaintext);

        var decrypted = LargeBlobArray.TryDecrypt(key, entry);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void TryDecrypt_WithWrongKey_ReturnsNull()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var wrongKey = RandomNumberGenerator.GetBytes(32);

        var entry = LargeBlobArray.Encrypt(key, "secret"u8);

        var decrypted = LargeBlobArray.TryDecrypt(wrongKey, entry);

        Assert.Null(decrypted);
    }
}
