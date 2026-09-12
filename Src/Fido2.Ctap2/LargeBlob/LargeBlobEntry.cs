using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// An element of the large-blob array: an AEAD_AES_256_GCM-encrypted, DEFLATE-compressed opaque
/// blob associated with a single credential via its largeBlobKey.
/// <para>See §6.10.3 of the CTAP 2.3 Proposed Standard.</para>
/// </summary>
public sealed class LargeBlobEntry
{
    /// <summary>
    /// AEAD_AES_256_GCM ciphertext, implicitly including the AEAD "authentication tag" at the end.
    /// </summary>
    public required byte[] Ciphertext { get; init; }

    /// <summary>
    /// AEAD_AES_256_GCM nonce. MUST be exactly 12 bytes long.
    /// </summary>
    public required byte[] Nonce { get; init; }

    /// <summary>
    /// The length, in bytes, of the uncompressed opaque large-blob data.
    /// </summary>
    public required long OrigSize { get; init; }

    internal CborMap ToCborObject()
    {
        return new CborMap
        {
            { 0x01, Ciphertext },
            { 0x02, Nonce },
            { 0x03, OrigSize }
        };
    }

    internal static LargeBlobEntry? TryDecode(CborObject cbor)
    {
        if (cbor is not CborMap map)
            return null;

        byte[]? ciphertext = null;
        byte[]? nonce = null;
        long? origSize = null;

        foreach (var (key, value) in map)
        {
            switch ((int)key)
            {
                case 0x01:
                    ciphertext = (byte[])value;
                    break;
                case 0x02:
                    nonce = (byte[])value;
                    break;
                case 0x03:
                    origSize = (long)value;
                    break;
            }
        }

        if (ciphertext is null || nonce is null || origSize is null)
            return null;

        return new LargeBlobEntry { Ciphertext = ciphertext, Nonce = nonce, OrigSize = origSize.Value };
    }
}
