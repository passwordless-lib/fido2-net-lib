using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using fido2_net_lib.Test;
using Fido2NetLib;
using Fido2NetLib.Objects;
using PeterO.Cbor;
using Xunit;

namespace Test.Attestation
{
    public class FidoU2f : Fido2Tests.Attestation
    {
        public FidoU2f()
        {
            _aaguid = Guid.Empty;
            _attestationObject.Add("fmt", "fido-u2f");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=U2FTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(notCAExt);

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));
                    var ecparams = ecdsaAtt.ExportParameters(true);

                    _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecparams.Q.X, ecparams.Q.Y);

                    var x = _credentialPublicKey.GetCBORObject()[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString();
                    var y = _credentialPublicKey.GetCBORObject()[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString();
                    var publicKeyU2F = new byte[1] { 0x4 }.Concat(x).Concat(y).ToArray();

                    var verificationData = new byte[1] { 0x00 };
                    verificationData = verificationData
                                        .Concat(_rpIdHash)
                                        .Concat(_clientDataHash)
                                        .Concat(_credentialID)
                                        .Concat(publicKeyU2F.ToArray())
                                        .ToArray();

                    byte[] signature = Fido2Tests.SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, verificationData, ecdsaAtt, null, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap().Add("x5c", X5c).Add("sig", signature));
               }
            }

        }
        [Fact]
        public void TestU2f()
        {
            var res = MakeAttestationResponse().Result;
            Assert.Equal("", res.ErrorMessage);
            Assert.Equal("ok", res.Status);
            Assert.True(_credentialID.SequenceEqual(res.Result.CredentialId));
            Assert.Equal(_signCount, res.Result.Counter);
        }
        [Fact]
        public void TestU2fWithAaguid()
        {
            _aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Aaguid was not empty parsing fido-u2f atttestation statement", ex.Result.Message);
        }
        [Fact]
        public void TestU2fMissingX5c()
        {
            _attestationObject["attStmt"].Set("x5c", null);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in fido - u2f attestation", ex.Result.Message);
        }
        [Fact]
        public void TestU2fX5cNotArray()
        {
            _attestationObject["attStmt"].Set("x5c", "boomerang");
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in fido - u2f attestation", ex.Result.Message);
        }
        [Fact]
        public void TestU2fX5cCountNotOne()
        {
            _attestationObject["attStmt"]
                .Set("x5c", CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0])).Add(CBORObject.FromObject(new byte[0])));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in fido - u2f attestation", ex.Result.Message);
        }
        [Fact]
        public void TestU2fX5cValueNotByteString()
        {
            _attestationObject["attStmt"].Set("x5c", "x".ToArray());
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Result.Message);
        }
        [Fact]
        public void TestU2fX5cValueZeroLengthByteString()
        {
            _attestationObject["attStmt"].Set("x5c", CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0])));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
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

                using (var attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    _attestationObject["attStmt"].Set("x5c", CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData)));
                    ;
                }
            }

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Attestation certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve", ex.Result.Message);
        }
        [Fact]
        public void TestU2fSigNull()
        {
            _attestationObject["attStmt"].Set("sig", null);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid fido-u2f attestation signature", ex.Result.Message);
        }
        [Fact]
        public void TestU2fSigNotByteString()
        {
            _attestationObject["attStmt"].Set("sig", "walrus");
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid fido-u2f attestation signature", ex.Result.Message);
        }
        [Fact]
        public void TestU2fSigByteStringZeroLen()
        {
            _attestationObject["attStmt"].Set("sig", CBORObject.FromObject(new byte[0]));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid fido-u2f attestation signature", ex.Result.Message);
        }
        [Fact]
        public void TestU2fSigNotASN1()
        {
            _attestationObject["attStmt"].Set("sig", CBORObject.FromObject(new byte[] { 0xf1, 0xd0 }));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Failed to decode fido-u2f attestation signature from ASN.1 encoded form", ex.Result.Message);
        }
        [Fact]
        public void TestU2fBadSig()
        {
            var sig = _attestationObject["attStmt"]["sig"].GetByteString();
            sig[15] ^= sig[15];
            _attestationObject["attStmt"].Set("sig", CBORObject.FromObject(sig));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid fido-u2f attestation signature", ex.Result.Message);
        }
    }
}
