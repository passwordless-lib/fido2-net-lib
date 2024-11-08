using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib;
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
}
