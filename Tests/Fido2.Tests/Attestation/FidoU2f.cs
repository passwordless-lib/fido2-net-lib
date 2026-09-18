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

        var ecParams = ecdsaAtt.ExportParameters(true);

        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecParams.Q.X, ecParams.Q.Y);

        var x = (byte[])_credentialPublicKey.GetCborObject()[COSE.KeyTypeParameter.X];
        var y = (byte[])_credentialPublicKey.GetCborObject()[COSE.KeyTypeParameter.Y];

        byte[] publicKeyU2F = [0x4, .. x, .. y];

        byte[] verificationData = [
            0x00,
            .. _rpIdHash,
            .. _clientDataHash,
            .. _credentialID,
            .. publicKeyU2F
        ];

        byte[] signature = Fido2Tests.SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, verificationData, ecdsaAtt, null, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "x5c", x5c },
            { "sig", signature }
        });
    }

    [Fact]
    public async Task TestU2f()
    {
        var credential = await MakeAttestationResponseAsync();
        Assert.Equal(_aaguid, credential.AaGuid);
        Assert.Equal(_signCount, credential.SignCount);
        Assert.Equal("fido-u2f", credential.AttestationFormat);
        Assert.Equal("attca", credential.AttestationType);
        Assert.Equal(_credentialID, credential.Id);
        Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
        Assert.Equal("Test User", credential.User.DisplayName);
        Assert.Equal("testuser"u8.ToArray(), credential.User.Id);
        Assert.Equal("testuser", credential.User.Name);
        Assert.Equal(new[] { AuthenticatorTransport.Internal }, credential.Transports);
    }

    [Fact]
    public async Task TestU2fWithAaguid()
    {
        _aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Aaguid was not empty parsing fido-u2f attestation statement", ex.Message);
    }

    [Fact]
    public async Task TestU2fMissingX5c()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("x5c", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Message);
    }

    [Fact]
    public async Task TestU2fX5cNotArray()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborTextString("boomerang"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Message);
    }

    [Fact]
    public async Task TestU2fX5cCountNotOne()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborArray { new byte[0], new byte[0] });
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Message);
    }

    [Fact]
    public async Task TestU2fX5cValueNotByteString()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborTextString("x"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Message);
    }

    [Fact]
    public async Task TestU2fX5cValueZeroLengthByteString()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborArray { new byte[0] });
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Message);
    }

    [Fact]
    public async Task TestU2fAttCertNotP256()
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

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Attestation certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve", ex.Message);
    }

    [Fact]
    public async Task TestU2fSigNull()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("sig", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid fido-u2f attestation signature", ex.Message);
    }
    [Fact]
    public async Task TestU2fSigNotByteString()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("sig", new CborTextString("walrus"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid fido-u2f attestation signature", ex.Message);
    }
    [Fact]
    public async Task TestU2fSigByteStringZeroLen()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("sig", new CborByteString(new byte[0]));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid fido-u2f attestation signature", ex.Message);
    }
    [Fact]
    public async Task TestU2fSigNotASN1()
    {
        ((CborMap)_attestationObject["attStmt"]).Set("sig", new CborByteString([0xf1, 0xd0]));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Failed to decode fido-u2f attestation signature from ASN.1 encoded form", ex.Message);
    }
    [Fact]
    public async Task TestU2fBadSig()
    {
        var attnStmt = (CborMap)_attestationObject["attStmt"];
        var sig = (byte[])attnStmt["sig"];
        sig[^1] ^= 0xff;
        attnStmt.Set("sig", new CborByteString(sig));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid fido-u2f attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestU2fAttCertNotEc()
    {
        using var rsaAtt = RSA.Create(2048);
        var attRequest = new CertificateRequest("CN=U2FTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", rsaAtt, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        attRequest.CertificateExtensions.Add(notCAExt);
        using X509Certificate2 attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2));

        ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborArray { attestnCert.RawData });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Attestation certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve", ex.Message);
    }

    [Fact]
    public async Task TestU2fCredentialPublicKeyNotEc2()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.RSA, COSE.Algorithm.RS256, rsaParams.Modulus, rsaParams.Exponent);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("fido-u2f attestation requires an EC2 credential public key, got RSA", ex.Message);
    }

    [Fact]
    public async Task TestU2fCredentialPublicKeyCoordinateNot32Bytes()
    {
        // the same P-256 point with a leading zero octet on each coordinate: a valid key, but not the 32-byte
        // coordinates the U2F public key format is assembled from. Corrupting the coordinates on the already-built
        // CredentialPublicKey (rather than constructing a new one from the bad bytes) avoids feeding an invalid EC
        // point through ECDsa.Create, whose validation is stricter on some platforms than others.
        //
        // CredentialPublicKey.CreateECDsa validates coordinate length itself before ever reaching ECDsa.Create, so
        // this is rejected while parsing the attested credential data -- before the fido-u2f verifier's own,
        // otherwise-unreachable copy of the same check (WebAuthn 8.6 step 4a/4b) would run.
        var cpk = _credentialPublicKey.GetCborObject();
        var x = (byte[])cpk[COSE.KeyTypeParameter.X];
        var y = (byte[])cpk[COSE.KeyTypeParameter.Y];
        cpk.Set(COSE.KeyTypeParameter.X, [0x00, .. x]);
        cpk.Set(COSE.KeyTypeParameter.Y, [0x00, .. y]);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Equal("EC2 credential public key x-coordinate must be 32 bytes for curve P256, got 33", ex.Message);
    }
}
