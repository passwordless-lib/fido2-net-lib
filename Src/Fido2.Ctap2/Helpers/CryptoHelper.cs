using System.Security.Cryptography;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

public static class CryptoHelper
{
    internal static ReadOnlySpan<byte> DefaultIV => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    internal static byte[] AesCbcDefaultIvNoPadding(byte[] key, ReadOnlySpan<byte> data)
    {
        using var aes = Aes.Create();

        aes.Key = key;

        // AES256-CBC(sharedSecret, IV = 0, data).
        return aes.EncryptCbc(data, iv: DefaultIV, PaddingMode.None);
    }

    public static byte[] GenerateSharedSecret(CredentialPublicKey authenticatorKeyAgreementKey, out CredentialPublicKey platformKeyAgreementKey)
    {
        using var authenticatorKey = authenticatorKeyAgreementKey.CreateECDsa(); // public key
        using var platformKey = ECDsa.Create(); // private key

        platformKey.GenerateKey(ECCurve.NamedCurves.nistP256);

        platformKeyAgreementKey = new CredentialPublicKey(platformKey, COSE.Algorithm.ES256);

        using var pub = ECDiffieHellman.Create(authenticatorKey.ExportParameters(false));
        using var pri = ECDiffieHellman.Create(platformKey.ExportParameters(true));

        byte[] sharedSecret = pri.DeriveKeyFromHash(pub.PublicKey, HashAlgorithmName.SHA256); // Same as pri.DeriveKeyMaterial(pub.PublicKey)

        return sharedSecret;
    }

    public static byte[] ZeroPadRight(byte[] value, int length)
    {
        if (value.Length < length)
        {
            var padded = new byte[64];

            value.AsSpan().CopyTo(padded);

            return padded;
        }

        return value;
    }
}
