using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test.Attestation;

public class FidoU2f : Fido2Tests.Attestation
{
    public FidoU2f()
    {
        _aaguid = Guid.Empty;
        _attestationObject.Add("fmt", "fido-u2f");
        using var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attRequest = new CertificateRequest("CN=U2FTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

        attRequest.CertificateExtensions.Add(notCAExt);

        using X509Certificate2 attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2));

        var x5c = new CborArray {
            attestnCert.RawData
        };

        var ecparams = ecdsaAtt.ExportParameters(true);

        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecparams.Q.X, ecparams.Q.Y);

        var x = (byte[])_credentialPublicKey.GetCborObject()[COSE.KeyTypeParameter.X];
        var y = (byte[])_credentialPublicKey.GetCborObject()[COSE.KeyTypeParameter.Y];

        byte[] publicKeyU2F = DataHelper.Concat(new byte[1] { 0x4 }, x, y);

        byte[] verificationData = DataHelper.Concat(
            new byte[1] { 0x00 },
            _rpIdHash,
            _clientDataHash,
            _credentialID,
            publicKeyU2F
        );

        byte[] signature = Fido2Tests.SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, verificationData, ecdsaAtt, null, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "x5c", x5c },
            { "sig", signature }
        });
    }

    [Fact]
    public async void TestU2f()
    {
        var res = await MakeAttestationResponseAsync();
        Assert.Equal(string.Empty, res.ErrorMessage);
        Assert.Equal("ok", res.Status);
        Assert.Equal(_aaguid, res.Result.AaGuid);
        Assert.Equal(_signCount, res.Result.Counter);
        Assert.Equal("fido-u2f", res.Result.CredType);
        Assert.Equal(_credentialID, res.Result.CredentialId);
        Assert.Null(res.Result.ErrorMessage);
        Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
        Assert.Null(res.Result.Status);
        Assert.Equal("Test User", res.Result.User.DisplayName);
        Assert.Equal("testuser"u8.ToArray(), res.Result.User.Id);
        Assert.Equal("testuser", res.Result.User.Name);
    }

    [Fact]
    public async Task TestU2fWithAaguid()
    {
        _aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Aaguid was not empty parsing fido-u2f atttestation statement", ex.Message);
    }

    [Fact]
    public void TestU2fMissingX5c()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("x5c", CborNull.Instance);
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Result.Message);
    }

    [Fact]
    public void TestU2fX5cNotArray()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborTextString("boomerang"));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Result.Message);
    }

    [Fact]
    public void TestU2fX5cCountNotOne()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborArray { new byte[0], new byte[0] });
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Result.Message);
    }

    [Fact]
    public void TestU2fX5cValueNotByteString()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborTextString("x"));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Result.Message);
    }

    [Fact]
    public void TestU2fX5cValueZeroLengthByteString()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborArray { new byte[0] });
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Result.Message);
    }

    [Fact]
    public void TestU2fAttCertNotP256()
    {
        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP384))
        {
            var attRequest = new CertificateRequest("CN=U2FTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            attRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));

            using var attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2));
            var attnStmt = (CborMap)_attestationObject["attStmt"];
            attnStmt.Set("x5c", new CborArray { attestnCert.RawData });
        }

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Attestation certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve", ex.Result.Message);
    }

    [Fact]
    public void TestU2fSigNull()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("sig", CborNull.Instance);
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid fido-u2f attestation signature", ex.Result.Message);
    }
    [Fact]
    public void TestU2fSigNotByteString()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("sig", new CborTextString("walrus"));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid fido-u2f attestation signature", ex.Result.Message);
    }
    [Fact]
    public void TestU2fSigByteStringZeroLen()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("sig", new CborByteString(new byte[0]));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid fido-u2f attestation signature", ex.Result.Message);
    }
    [Fact]
    public void TestU2fSigNotASN1()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("sig", new CborByteString(new byte[] { 0xf1, 0xd0 }));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Failed to decode fido-u2f attestation signature from ASN.1 encoded form", ex.Result.Message);
    }
    [Fact]
    public void TestU2fBadSig()
    {
        var attnStmt = (CborMap)_attestationObject["attStmt"];
        var sig = (byte[])attnStmt["sig"];
        sig[^1] ^= 0xff;
        attnStmt.Set("sig", new CborByteString(sig));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid fido-u2f attestation signature", ex.Result.Message);
    }
}
