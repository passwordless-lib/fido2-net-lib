using System.Security.Cryptography;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// PIN/UV Auth Protocol One, per §6.5.6 of the CTAP 2.3 Proposed Standard.
/// </summary>
public sealed class PinUvAuthProtocolOne : IPinUvAuthProtocol
{
    public static readonly PinUvAuthProtocolOne Instance = new();

    public int Version => 1;

    /// <summary>kdf(Z) = SHA-256(Z).</summary>
    public byte[] GenerateSharedSecret(CredentialPublicKey authenticatorKeyAgreementKey, out CredentialPublicKey platformKeyAgreementKey)
    {
        byte[] z = CryptoHelper.DeriveRawSharedPointZ(authenticatorKeyAgreementKey, out platformKeyAgreementKey);

        return SHA256.HashData(z);
    }

    /// <summary>The AES-256-CBC encryption of demPlaintext using an all-zero IV. No padding.</summary>
    public byte[] Encrypt(byte[] key, ReadOnlySpan<byte> demPlaintext)
    {
        return CryptoHelper.AesCbcDefaultIvNoPadding(key, demPlaintext);
    }

    /// <summary>The AES-256-CBC decryption of demCiphertext using an all-zero IV.</summary>
    public byte[] Decrypt(byte[] key, byte[] demCiphertext)
    {
        if (demCiphertext.Length % 16 != 0)
            throw new CryptographicException("Ciphertext length must be a multiple of the AES block length.");

        using var aes = Aes.Create();
        aes.Key = key;

        return aes.DecryptCbc(demCiphertext, CryptoHelper.DefaultIV, PaddingMode.None);
    }

    /// <summary>The first 16 bytes of HMAC-SHA-256(key, message).</summary>
    public byte[] Authenticate(byte[] key, ReadOnlySpan<byte> message)
    {
        return CryptoHelper.AuthenticateProtocolOne(key, message);
    }

    public bool Verify(byte[] key, ReadOnlySpan<byte> message, byte[] signature)
    {
        if (signature.Length != 16)
            return false;

        return CryptographicOperations.FixedTimeEquals(Authenticate(key, message), signature);
    }
}
