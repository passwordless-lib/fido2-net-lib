using System.IO.Compression;
using System.Security.Cryptography;

using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Helpers for encoding/decoding the CTAP2 serialized large-blob array, and for
/// encrypting/decrypting the per-credential opaque data stored within it.
/// <para>See §6.10 of the CTAP 2.3 Proposed Standard.</para>
/// </summary>
public static class LargeBlobArray
{
    private const int TrailingHashLength = 16;
    private static readonly byte[] AssociatedDataPrefix = "blob"u8.ToArray();

    /// <summary>
    /// The value of the serialized large-blob array on a fresh authenticator, as well as
    /// immediately after a reset: an empty CBOR array (0x80) followed by
    /// <c>LEFT(SHA-256(h'80'), 16)</c>.
    /// </summary>
    public static byte[] InitialSerializedArray { get; } = BuildInitial();

    private static byte[] BuildInitial()
    {
        byte[] emptyArray = [0x80];
        byte[] hash = SHA256.HashData(emptyArray);

        var result = new byte[emptyArray.Length + TrailingHashLength];
        emptyArray.CopyTo(result, 0);
        hash.AsSpan(0, TrailingHashLength).CopyTo(result.AsSpan(emptyArray.Length));

        return result;
    }

    /// <summary>
    /// Decodes a serialized large-blob array, verifying the trailing SHA-256 hash. Per §6.10.2,
    /// if the hash does not match, the platform MUST discard the configuration and act as if the
    /// initial serialized large-blob array was received; this is surfaced here as
    /// <paramref name="entries"/> being empty and the method returning <c>false</c>, rather than
    /// throwing, so callers can implement that fallback themselves.
    /// </summary>
    /// <returns><c>true</c> if the trailing hash matched and <paramref name="entries"/> reflects the array's contents.</returns>
    public static bool TryDecode(byte[] serializedLargeBlobArray, out IReadOnlyList<LargeBlobEntry> entries)
    {
        entries = [];

        if (serializedLargeBlobArray.Length < TrailingHashLength + 1)
            return false;

        int arrayLength = serializedLargeBlobArray.Length - TrailingHashLength;
        var arrayBytes = serializedLargeBlobArray.AsSpan(0, arrayLength);
        var storedHash = serializedLargeBlobArray.AsSpan(arrayLength, TrailingHashLength);

        Span<byte> computedHash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(arrayBytes, computedHash);

        if (!storedHash.SequenceEqual(computedHash[..TrailingHashLength]))
            return false;

        var array = (CborArray)CborObject.Decode(arrayBytes.ToArray());

        var result = new List<LargeBlobEntry>(array.Length);

        foreach (var element in array)
        {
            if (LargeBlobEntry.TryDecode(element) is { } entry)
            {
                result.Add(entry);
            }
        }

        entries = result;

        return true;
    }

    /// <summary>
    /// Encodes a set of large-blob entries into a serialized large-blob array, appending the
    /// trailing SHA-256 hash required by §6.10.2. The maps and array are encoded using
    /// <see cref="CborObject.Encode"/>'s canonical rules, per the platform requirement in §6.10.2.
    /// </summary>
    public static byte[] Encode(IEnumerable<LargeBlobEntry> entries)
    {
        var array = new CborArray();

        foreach (var entry in entries)
        {
            array.Add(entry.ToCborObject());
        }

        byte[] arrayBytes = array.Encode();
        byte[] hash = SHA256.HashData(arrayBytes);

        var result = new byte[arrayBytes.Length + TrailingHashLength];
        arrayBytes.CopyTo(result, 0);
        hash.AsSpan(0, TrailingHashLength).CopyTo(result.AsSpan(arrayBytes.Length));

        return result;
    }

    /// <summary>
    /// Compresses and encrypts opaque per-credential large-blob data for storage, per §6.10.3/6.10.5.
    /// </summary>
    /// <param name="largeBlobKey">The 32-byte largeBlobKey associated with the target credential.</param>
    /// <param name="plaintext">The opaque large-blob data to store.</param>
    public static LargeBlobEntry Encrypt(byte[] largeBlobKey, ReadOnlySpan<byte> plaintext)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(largeBlobKey.Length, 32, nameof(largeBlobKey));

        byte[] compressed = Deflate(plaintext);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[compressed.Length + 16]; // + AEAD tag

        using var aesGcm = new AesGcm(largeBlobKey, tagSizeInBytes: 16);

        var associatedData = BuildAssociatedData(plaintext.Length);

        aesGcm.Encrypt(nonce, compressed, ciphertext.AsSpan(0, compressed.Length), ciphertext.AsSpan(compressed.Length), associatedData);

        return new LargeBlobEntry { Ciphertext = ciphertext, Nonce = nonce, OrigSize = plaintext.Length };
    }

    /// <summary>
    /// Attempts to decrypt and decompress a large-blob entry with the given largeBlobKey, per §6.10.4.
    /// Returns <c>null</c> if decryption or decompression fails (e.g. because the entry belongs to a
    /// different credential), matching the "trial decryption" approach described there.
    /// </summary>
    public static byte[]? TryDecrypt(byte[] largeBlobKey, LargeBlobEntry entry)
    {
        if (largeBlobKey.Length != 32 || entry.Ciphertext.Length < 16 || entry.Nonce.Length != 12)
            return null;

        int compressedLength = entry.Ciphertext.Length - 16;
        var compressed = new byte[compressedLength];

        try
        {
            using var aesGcm = new AesGcm(largeBlobKey, tagSizeInBytes: 16);

            var associatedData = BuildAssociatedData(entry.OrigSize);

            aesGcm.Decrypt(
                entry.Nonce,
                entry.Ciphertext.AsSpan(0, compressedLength),
                entry.Ciphertext.AsSpan(compressedLength),
                compressed,
                associatedData);
        }
        catch (CryptographicException)
        {
            return null;
        }

        try
        {
            byte[] plaintext = Inflate(compressed);

            return plaintext.Length == entry.OrigSize ? plaintext : null;
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    private static byte[] BuildAssociatedData(long origSize)
    {
        var result = new byte[AssociatedDataPrefix.Length + 8];
        AssociatedDataPrefix.CopyTo(result, 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(AssociatedDataPrefix.Length), (ulong)origSize);

        return result;
    }

    private static byte[] Deflate(ReadOnlySpan<byte> data)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            deflate.Write(data);
        }

        return output.ToArray();
    }

    private static byte[] Inflate(byte[] compressed)
    {
        using var input = new MemoryStream(compressed);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();

        deflate.CopyTo(output);

        return output.ToArray();
    }
}
