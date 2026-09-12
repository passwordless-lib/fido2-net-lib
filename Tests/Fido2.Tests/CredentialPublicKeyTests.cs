using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace fido2_net_lib.Test;

public class CredentialPublicKeyTests
{
    [Theory]
    [InlineData("1.3.132.0.10", COSE.Algorithm.ES256K)] // secP256k1
    [InlineData("1.2.840.10045.3.1.7", COSE.Algorithm.ES256)]  // P256
    [InlineData("1.3.132.0.34", COSE.Algorithm.ES384)]  // P384
    [InlineData("1.3.132.0.35", COSE.Algorithm.ES512)]  // P512
    public void CanUseECCurves(string oid, COSE.Algorithm alg)
    {
        if (OperatingSystem.IsMacOS() && alg is COSE.Algorithm.ES256K)
        {
            return;
        }

        byte[] signedData = RandomNumberGenerator.GetBytes(64);

        using var ecDsa = ECDsa.Create(ECCurve.CreateFromValue(oid));

        var signature = SignatureHelper.EcDsaSigFromSig(ecDsa.SignData(signedData, CryptoUtils.HashAlgFromCOSEAlg(alg)), ecDsa.KeySize);

        var credentialPublicKey = new CredentialPublicKey(ecDsa, alg);

        using var decodedPublicKey = credentialPublicKey.CreateECDsa();

        var decodedEcDsaParams = decodedPublicKey.ExportParameters(false);

        // NOTES
        // - the oid.value is not set for secP256k1
        // - macOS does not support the secP256k1 curve

        if (decodedEcDsaParams.Curve.Oid?.Value != null)
        {
            Assert.Equal(oid, decodedEcDsaParams.Curve.Oid.Value);
        }

        Assert.True(credentialPublicKey.Verify(signedData, signature));
    }

    [Theory]
    [InlineData("A501020326200121581F6F56E6590BD91D39744F83A820E8B3FBB6608DA583794091538296D1DA73E2225820B0A65E0B18D3189DA3B4A7036202ADF65A6B68EFF8C24825532D7A04386AE628", 0x80131501)]
    public void InvalidCoseKey(string str, uint hresult)
    {
        var cpkBytes = Convert.FromHexString(str);
        var ex = Assert.Throws<CryptographicException>(() => new CredentialPublicKey(cpkBytes));
        Assert.True(((uint)ex.HResult) == hresult);
    }

    [Fact]
    public void OkpCertificate()
    {
        X509Certificate2 okpCert = new(X509CertificateHelper.CreateFromBase64String("MIIBhTCCATegAwIBAgIUfKk9eVV+OkGNxxguVYluGHPPI+swBQYDK2VwMDgxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhGbG9yaWRzYTEWMBQGA1UECgwNRklETzItTkVULUxJQjAeFw0yNDExMDQwMDM3MDNaFw0yNDEyMDQwMDM3MDNaMDgxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhGbG9yaWRzYTEWMBQGA1UECgwNRklETzItTkVULUxJQjAqMAUGAytlcAMhAJ2oFxsqEgM4DiMSJNskAYoKf55FXZhrde4Ho2UMJoKuo1MwUTAdBgNVHQ4EFgQUyhKwoqOmiB3UeXztoIPueEi7qSgwHwYDVR0jBBgwFoAUyhKwoqOmiB3UeXztoIPueEi7qSgwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQArZ82PaihKfiOHNDPCmax/vgsuMlJcQsAywcQFZfaRiNyU5Cq7hwOvNlA1wl1j9hZjV/SiPsfNSgY7nwTGf9cE"u8));
        CredentialPublicKey cpk = new(okpCert, COSE.Algorithm.EdDSA);
    }

    [Fact]
    public void Ed448IsRefusedAsInvalidRatherThanCrashing()
    {
        byte[] x = RandomNumberGenerator.GetBytes(57); // Ed448 public keys are 57 bytes

        // WebAuthn L3 §5.8.5: "Keys with algorithm -8 (EdDSA) MUST specify 6 (Ed25519) as the crv parameter."
        // An Ed448 key is expected to declare the fully-specified algorithm -53 instead, so alg=EdDSA with
        // crv=Ed448 is invalid rather than merely unimplemented.
        var ex = Assert.Throws<Fido2VerificationException>(() =>
            Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed448, x));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
    }

    [Fact]
    public void FullySpecifiedEd448IsUnimplemented()
    {
        // COSE.Algorithm.Ed448 (-53) is the fully-specified algorithm for an Ed448 key, as opposed to
        // EdDSA (-8) with crv=Ed448, which is rejected as invalid rather than unimplemented above.
        byte[] x = RandomNumberGenerator.GetBytes(57);

        var ex = Assert.Throws<Fido2VerificationException>(() =>
            Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.Ed448, COSE.EllipticCurve.Ed448, x));

        Assert.Equal(Fido2ErrorCode.UnimplementedAlgorithm, ex.Code);
    }

    [Fact]
    public void UnknownKeyTypeIsRejected()
    {
        var cpk = new CborMap();
        cpk.Add(COSE.KeyCommonParameter.KeyType, COSE.KeyType.Reserved);
        cpk.Add(COSE.KeyCommonParameter.Alg, COSE.Algorithm.ES256);

        var ex = Assert.Throws<Fido2VerificationException>(() => new CredentialPublicKey(cpk));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Contains("Missing or unknown kty", ex.Message);
    }

    [Fact]
    public void RejectsAnEC2KeyWithACompressedYCoordinate()
    {
        // A compressed point encodes y as a sign-bit rather than a byte string; WebAuthn L3 §5.8.5 requires
        // the uncompressed point form, so this is a malformed key rather than one to decompress.
        var cpk = new CborMap();
        cpk.Add(COSE.KeyCommonParameter.KeyType, COSE.KeyType.EC2);
        cpk.Add(COSE.KeyCommonParameter.Alg, COSE.Algorithm.ES256);
        cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)COSE.EllipticCurve.P256);
        cpk.Add(COSE.KeyTypeParameter.X, RandomNumberGenerator.GetBytes(32));
        cpk.Add((int)COSE.KeyTypeParameter.Y, 1L);

        var ex = Assert.Throws<Fido2VerificationException>(() => new CredentialPublicKey(cpk));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Contains("uncompressed point form", ex.Message);
    }

    [Theory]
    [InlineData(COSE.Algorithm.ESP256)]
    [InlineData(COSE.Algorithm.ESP384)]
    [InlineData(COSE.Algorithm.ESP512)]
    public void FullySpecifiedEcdsaAlgorithmsFixTheirOwnCurve(COSE.Algorithm alg)
    {
        // ESP256/384/512 each pin their curve directly, so crv is not consulted for them -- unlike
        // ES256/384/512/ES256K, which go through CurveFromAlgAndCrv below.
        ECCurve curve = alg switch
        {
            COSE.Algorithm.ESP256 => ECCurve.NamedCurves.nistP256,
            COSE.Algorithm.ESP384 => ECCurve.NamedCurves.nistP384,
            COSE.Algorithm.ESP512 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentOutOfRangeException(nameof(alg)),
        };

        byte[] signedData = RandomNumberGenerator.GetBytes(64);
        using var ecDsa = ECDsa.Create(curve);
        var signature = SignatureHelper.EcDsaSigFromSig(ecDsa.SignData(signedData, CryptoUtils.HashAlgFromCOSEAlg(alg)), ecDsa.KeySize);

        var credentialPublicKey = new CredentialPublicKey(ecDsa, alg);
        using var decodedPublicKey = credentialPublicKey.CreateECDsa();

        Assert.True(credentialPublicKey.Verify(signedData, signature));
    }

    [Fact]
    public void RejectsAnEcdsaAlgorithmPairedWithTheWrongCurve()
    {
        // ES256 pins P-256 (WebAuthn L3 §5.8.5); a key that declares crv=P-384 alongside alg=ES256 is
        // malformed rather than merely using an unsupported curve.
        using var ecDsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var keyParams = ecDsa.ExportParameters(false);

        var cpk = new CborMap();
        cpk.Add(COSE.KeyCommonParameter.KeyType, COSE.KeyType.EC2);
        cpk.Add(COSE.KeyCommonParameter.Alg, COSE.Algorithm.ES256);
        cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)COSE.EllipticCurve.P384);
        cpk.Add(COSE.KeyTypeParameter.X, keyParams.Q.X!);
        cpk.Add(COSE.KeyTypeParameter.Y, keyParams.Q.Y!);

        var ex = Assert.Throws<Fido2VerificationException>(() => new CredentialPublicKey(cpk));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Contains("is not valid with curve", ex.Message);
    }

    [Fact]
    public void RejectsAnRsaKeyWithANonRsaAlgorithm()
    {
        // The key type (RSA) and the algorithm (ES256) disagree; nothing validates this pairing until
        // Verify() actually needs the RSA signature padding for the declared algorithm.
        using var rsa = RSA.Create();
        var rsaParams = rsa.ExportParameters(false);
        var cpk = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.RSA, COSE.Algorithm.ES256, rsaParams.Modulus, rsaParams.Exponent);

        byte[] data = RandomNumberGenerator.GetBytes(64);
        byte[] signature = RandomNumberGenerator.GetBytes(32);

        var ex = Assert.Throws<Fido2VerificationException>(() => cpk.Verify(data, signature));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Contains("Missing or unknown alg", ex.Message);
    }
}
