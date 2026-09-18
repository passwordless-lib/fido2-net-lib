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
    // A 31-byte (not 32) EC2 x-coordinate. Left to ECDsa.Create, this surfaces as a raw CryptographicException
    // whose exact type/HResult depends on the platform's crypto backend; CredentialPublicKey now rejects the
    // malformed coordinate length itself first, so the result is a Fido2VerificationException everywhere.
    [InlineData("A501020326200121581F6F56E6590BD91D39744F83A820E8B3FBB6608DA583794091538296D1DA73E2225820B0A65E0B18D3189DA3B4A7036202ADF65A6B68EFF8C24825532D7A04386AE628")]
    public void InvalidCoseKey(string str)
    {
        var cpkBytes = Convert.FromHexString(str);
        var ex = Assert.Throws<Fido2VerificationException>(() => new CredentialPublicKey(cpkBytes));
        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Equal("EC2 credential public key x-coordinate must be 32 bytes for curve P256, got 31", ex.Message);
    }

    [Fact]
    public void OkpCertificate()
    {
        X509Certificate2 okpCert = new(X509CertificateHelper.CreateFromBase64String("MIIBhTCCATegAwIBAgIUfKk9eVV+OkGNxxguVYluGHPPI+swBQYDK2VwMDgxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhGbG9yaWRzYTEWMBQGA1UECgwNRklETzItTkVULUxJQjAeFw0yNDExMDQwMDM3MDNaFw0yNDEyMDQwMDM3MDNaMDgxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhGbG9yaWRzYTEWMBQGA1UECgwNRklETzItTkVULUxJQjAqMAUGAytlcAMhAJ2oFxsqEgM4DiMSJNskAYoKf55FXZhrde4Ho2UMJoKuo1MwUTAdBgNVHQ4EFgQUyhKwoqOmiB3UeXztoIPueEi7qSgwHwYDVR0jBBgwFoAUyhKwoqOmiB3UeXztoIPueEi7qSgwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQArZ82PaihKfiOHNDPCmax/vgsuMlJcQsAywcQFZfaRiNyU5Cq7hwOvNlA1wl1j9hZjV/SiPsfNSgY7nwTGf9cE"u8));
        CredentialPublicKey cpk = new(okpCert, COSE.Algorithm.EdDSA);
    }

    [Fact]
    public void Ed448IsRefusedAsUnimplementedRatherThanCrashing()
    {
        byte[] x = RandomNumberGenerator.GetBytes(57); // Ed448 public keys are 57 bytes

        var ex = Assert.Throws<Fido2VerificationException>(() =>
            Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed448, x));

        Assert.Equal(Fido2ErrorCode.UnimplementedAlgorithm, ex.Code);
    }

    // Each of these is reachable with attacker-chosen values (a credential public key in authenticator data, or an
    // attestation statement's alg paired with its certificate's key) and used to escape as InvalidOperationException.
    [Fact]
    public void UnknownKeyTypeIsAVerificationFailure()
    {
        var cpk = new CborMap {
            { COSE.KeyCommonParameter.KeyType, COSE.KeyType.Symmetric },
            { COSE.KeyCommonParameter.Alg, COSE.Algorithm.ES256 }
        };

        var ex = Assert.Throws<Fido2VerificationException>(() => new CredentialPublicKey(cpk));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Equal("Missing or unknown kty Symmetric", ex.Message);
    }

    [Theory]
    [InlineData(COSE.Algorithm.ES384, COSE.EllipticCurve.P256, "Algorithm ES384 cannot be used with an EC2 key on curve P256")]
    [InlineData(COSE.Algorithm.RS256, COSE.EllipticCurve.P256, "Algorithm RS256 cannot be used with an EC2 key on curve P256")]
    [InlineData(COSE.Algorithm.ES256, COSE.EllipticCurve.Ed25519, "Algorithm ES256 cannot be used with an EC2 key on curve Ed25519")]
    public void MismatchedEcAlgorithmAndCurveIsAVerificationFailure(COSE.Algorithm alg, COSE.EllipticCurve crv, string expectedMessage)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);

        var ex = Assert.Throws<Fido2VerificationException>(() =>
            Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, alg, crv, ecParams.Q.X, ecParams.Q.Y));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Equal(expectedMessage, ex.Message);
    }

    [Fact]
    public void RsaKeyWithNonRsaAlgorithmIsAVerificationFailure()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var cpk = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.RSA, COSE.Algorithm.ES256, rsaParams.Modulus, rsaParams.Exponent);

        var ex = Assert.Throws<Fido2VerificationException>(() => cpk.Verify(new byte[32], new byte[256]));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Equal("Algorithm ES256 cannot be used with an RSA key", ex.Message);
    }

    [Fact]
    public void OkpKeyWithNonEdDsaAlgorithmIsAVerificationFailure()
    {
        Fido2Tests.MakeEdDSA(out _, out var publicKey, out _);

        var ex = Assert.Throws<Fido2VerificationException>(() =>
            Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.ES256, COSE.EllipticCurve.Ed25519, publicKey));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Equal("Algorithm ES256 cannot be used with an OKP key", ex.Message);
    }

    [Fact]
    public void UnknownCertificateKeyAlgorithmIsAVerificationFailure()
    {
        var ex = Assert.Throws<Fido2VerificationException>(() => COSE.GetKeyTypeFromOid("1.2.840.10040.4.1")); // id-dsa

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Equal("Unknown public key algorithm OID 1.2.840.10040.4.1", ex.Message);
    }
}
