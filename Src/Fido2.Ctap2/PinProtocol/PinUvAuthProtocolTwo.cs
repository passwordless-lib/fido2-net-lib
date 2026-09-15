using System.Security.Cryptography;
using System.Text;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// PIN/UV Auth Protocol Two, per §6.5.7 of the CTAP 2.3 Proposed Standard. Intended to aid FIPS
/// certification of authenticators; support for it is mandatory in some cases (see §9).
/// </summary>
/// <remarks>
/// Inherits protocol one's behavior except where overridden here: <c>kdf</c> uses HKDF-SHA-256
/// instead of a bare SHA-256 (producing a 64-byte shared secret split into a 32-byte HMAC key
/// followed by a 32-byte AES key), <c>encrypt</c>/<c>decrypt</c> use a random IV instead of an
/// all-zero one, and <c>authenticate</c>/<c>verify</c> use the full 32-byte HMAC-SHA-256 output
/// rather than truncating to 16 bytes. The pinUvAuthToken length for this protocol MUST be 32 bytes.
/// </remarks>
public sealed class PinUvAuthProtocolTwo : IPinUvAuthProtocol
{
    public static readonly PinUvAuthProtocolTwo Instance = new();

    private static readonly byte[] ZeroSalt32 = new byte[32];
    private static readonly byte[] HmacKeyInfo = "CTAP2 HMAC key"u8.ToArray();
    private static readonly byte[] AesKeyInfo = "CTAP2 AES key"u8.ToArray();

    public int Version => 2;

    /// <summary>
    /// kdf(Z) = HKDF-SHA-256(salt=32×0x00, IKM=Z, L=32, info="CTAP2 HMAC key")
    ///        || HKDF-SHA-256(salt=32×0x00, IKM=Z, L=32, info="CTAP2 AES key").
    /// The two invocations are independent; this cannot be equivalently computed as a single
    /// HKDF call with L=64.
    /// </summary>
    public byte[] GenerateSharedSecret(CredentialPublicKey authenticatorKeyAgreementKey, out CredentialPublicKey platformKeyAgreementKey)
    {
        byte[] z = CryptoHelper.DeriveRawSharedPointZ(authenticatorKeyAgreementKey, out platformKeyAgreementKey);

        byte[] hmacKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, ZeroSalt32, HmacKeyInfo);
        byte[] aesKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, ZeroSalt32, AesKeyInfo);

        return [.. hmacKey, .. aesKey];
    }

    /// <summary>
    /// Discards the HMAC-key portion (first 32 bytes) of <paramref name="key"/>, then returns
    /// <c>iv || AES-256-CBC(aesKey, iv, demPlaintext)</c> for a fresh, random 16-byte <c>iv</c>.
    /// </summary>
    public byte[] Encrypt(byte[] key, ReadOnlySpan<byte> demPlaintext)
    {
        byte[] aesKey = GetAesKeyPortion(key);
        byte[] iv = RandomNumberGenerator.GetBytes(16);

        using var aes = Aes.Create();
        aes.Key = aesKey;

        byte[] ciphertext = aes.EncryptCbc(demPlaintext, iv, PaddingMode.None);

        return [.. iv, .. ciphertext];
    }

    /// <summary>
    /// Discards the HMAC-key portion (first 32 bytes) of <paramref name="key"/>, splits
    /// <paramref name="demCiphertext"/> into its leading 16-byte IV and the remaining ciphertext,
    /// and returns the AES-256-CBC decryption.
    /// </summary>
    public byte[] Decrypt(byte[] key, byte[] demCiphertext)
    {
        if (demCiphertext.Length < 16)
            throw new CryptographicException("Ciphertext must be at least 16 bytes (the IV) long.");

        byte[] aesKey = GetAesKeyPortion(key);
        var iv = demCiphertext.AsSpan(0, 16);
        var ciphertext = demCiphertext.AsSpan(16);

        using var aes = Aes.Create();
        aes.Key = aesKey;

        return aes.DecryptCbc(ciphertext, iv, PaddingMode.None);
    }

    /// <summary>
    /// Discards any bytes of <paramref name="key"/> beyond the first 32 (the HMAC-key portion;
    /// a no-op when <paramref name="key"/> is a 32-byte pinUvAuthToken), then returns the full
    /// HMAC-SHA-256(key, message) — unlike protocol one, not truncated.
    /// </summary>
    public byte[] Authenticate(byte[] key, ReadOnlySpan<byte> message)
    {
        byte[] hmacKey = key.Length > 32 ? key[..32] : key;

        return HMACSHA256.HashData(hmacKey, message);
    }

    public bool Verify(byte[] key, ReadOnlySpan<byte> message, byte[] signature)
    {
        if (signature.Length != 32)
            return false;

        return CryptographicOperations.FixedTimeEquals(Authenticate(key, message), signature);
    }

    private static byte[] GetAesKeyPortion(byte[] key) => key.AsSpan(32, 32).ToArray();
}
