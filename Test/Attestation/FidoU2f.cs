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
        public override CredentialPublicKey _credentialPublicKey { get { return _cpk; } }
        internal CredentialPublicKey _cpk;
        public FidoU2f()
        {
            _aaguid = Guid.Empty;
            _attestationObject.Add("fmt", "fido-u2f");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=U2FTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, false));

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));
                    var ecparams = ecdsaAtt.ExportParameters(true);

                    _cpk = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecparams.Q.X, ecparams.Q.Y);

                    var x = _cpk.GetCBORObject()[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString();
                    var y = _cpk.GetCBORObject()[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString();
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
        public void TestU2fMalformedX5c()
        {
            _attestationObject["attStmt"].Set("x5c", "x".ToArray());
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in fido-u2f attestation", ex.Result.Message);
        }
    }
}
