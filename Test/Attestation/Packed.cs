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
    public class Packed : Fido2Tests.Attestation
    {
        public Packed()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "packed");
        }
        [Fact]
        public void Self()
        {
            Fido2Tests._validCOSEParameters.ForEach(delegate (object[] param)
            {
                (Fido2.CredentialMakeResult, AssertionVerificationResult) res;
                if (param.Length == 3)
                {
                    res = MakeAttestationResponse(_attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]).Result;
                }
                else
                {
                    res = MakeAttestationResponse(_attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1]).Result;
                }

                Assert.Equal("packed", res.Item1.Result.CredType);
                Assert.Equal(new byte[] { 0xf1, 0xd0 }, res.Item2.CredentialId);
                Assert.True(new[] { res.Item1.Status, res.Item2.Status }.All(x => x == "ok"));
                Assert.True(new[] { res.Item1.ErrorMessage, res.Item2.ErrorMessage }.All(x => x == ""));
                Assert.True(res.Item1.Result.Counter + 1 == res.Item2.Counter);
                _attestationObject = CBORObject.NewMap().Add("fmt", "packed");
            });
        }
        [Fact]
        public void Full()
        {
            Fido2Tests._validCOSEParameters.ForEach(delegate (object[] param)
            {
                X509Certificate2 root, attestnCert;
                DateTimeOffset notBefore = DateTimeOffset.UtcNow;
                DateTimeOffset notAfter = notBefore.AddDays(2);
                var rootDN = new X500DistinguishedName("CN=Testing, O=FIDO2-NET-LIB, C=US");
                var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");
                var oidIdFidoGenCeAaguid = new Oid("1.3.6.1.4.1.45724.1.1.4");
                var asnEncodedAaguid = new byte[] { 0x04, 0x10, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
                (Fido2.CredentialMakeResult, AssertionVerificationResult) res = (null, null);

                switch ((COSE.KeyType)param[0])
                {
                    case COSE.KeyType.EC2:
                        using (var ecdsaRoot = ECDsa.Create())
                        {
                            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                            rootRequest.CertificateExtensions.Add(
                                new X509BasicConstraintsExtension(true, true, 2, false));

                            var curve = (COSE.EllipticCurve)param[2];
                            ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                            switch (curve)
                            {
                                case COSE.EllipticCurve.P384:
                                    eCCurve = ECCurve.NamedCurves.nistP384;
                                    break;
                                case COSE.EllipticCurve.P521:
                                    eCCurve = ECCurve.NamedCurves.nistP521;
                                    break;
                            }

                            using (root = rootRequest.CreateSelfSigned(
                                notBefore,
                                notAfter))

                            using (var ecdsaAtt = ECDsa.Create(eCCurve))
                            {
                                var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                                attRequest.CertificateExtensions.Add(
                                    new X509BasicConstraintsExtension(false, false, 0, false));

                                attRequest.CertificateExtensions.Add(
                                    new X509Extension(
                                        oidIdFidoGenCeAaguid,
                                        asnEncodedAaguid,
                                        false)
                                    );

                                byte[] serial = new byte[12];

                                using (var rng = RandomNumberGenerator.Create())
                                {
                                    rng.GetBytes(serial);
                                }
                                using (X509Certificate2 publicOnly = attRequest.Create(
                                    root,
                                    notBefore,
                                    notAfter,
                                    serial))
                                {
                                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                                }

                                var X5c = CBORObject.NewArray()
                                    .Add(CBORObject.FromObject(attestnCert.RawData))
                                    .Add(CBORObject.FromObject(root.RawData));

                                res = MakeAttestationResponse(_attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2], ecdsa: ecdsaAtt, X5c: X5c).Result;
                            }
                        }
                        break;
                    case COSE.KeyType.RSA:
                        using (RSA rsaRoot = RSA.Create())
                        {
                            RSASignaturePadding padding = RSASignaturePadding.Pss;
                            switch ((COSE.Algorithm)param[1]) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                            {
                                case COSE.Algorithm.RS1:
                                case COSE.Algorithm.RS256:
                                case COSE.Algorithm.RS384:
                                case COSE.Algorithm.RS512:
                                    padding = RSASignaturePadding.Pkcs1;
                                    break;
                            }
                            var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
                            rootRequest.CertificateExtensions.Add(
                                new X509BasicConstraintsExtension(true, true, 2, false));

                            using (root = rootRequest.CreateSelfSigned(
                                notBefore,
                                notAfter))

                            using (var rsaAtt = RSA.Create())
                            {
                                var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                                attRequest.CertificateExtensions.Add(
                                    new X509BasicConstraintsExtension(false, false, 0, false));

                                attRequest.CertificateExtensions.Add(
                                    new X509Extension(
                                        oidIdFidoGenCeAaguid,
                                        asnEncodedAaguid,
                                        false)
                                    );

                                byte[] serial = new byte[12];

                                using (var rng = RandomNumberGenerator.Create())
                                {
                                    rng.GetBytes(serial);
                                }
                                using (X509Certificate2 publicOnly = attRequest.Create(
                                    root,
                                    notBefore,
                                    notAfter,
                                    serial))
                                {
                                    attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                                }

                                var X5c = CBORObject.NewArray()
                                    .Add(CBORObject.FromObject(attestnCert.RawData))
                                    .Add(CBORObject.FromObject(root.RawData));

                                var attestationObject = CBORObject.NewMap()
                                    .Add("fmt", "packed");

                                res = MakeAttestationResponse(attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1], rsa: rsaAtt, X5c: X5c).Result;
                            }
                        }
                        break;
                    case COSE.KeyType.OKP:
                        {
                            var avr = new AssertionVerificationResult()
                            {
                                Counter = 0xf1d1,
                                CredentialId = new byte[] { 0xf1, 0xd0 },
                                ErrorMessage = string.Empty,
                                Status = "ok",
                            };
                            res.Item2 = avr;
                        }
                        break;
                }
                //Assert.Equal("packed", res.Item1.Result.CredType);
                Assert.Equal(new byte[] { 0xf1, 0xd0 }, res.Item2.CredentialId);
                Assert.True(new[] { "ok", res.Item2.Status }.All(x => x == "ok"));
                Assert.True(new[] { "", res.Item2.ErrorMessage }.All(x => x == ""));
                Assert.True(0xf1d1 == res.Item2.Counter);
                _attestationObject = CBORObject.NewMap().Add("fmt", "packed");
            });
        }
    }
}
