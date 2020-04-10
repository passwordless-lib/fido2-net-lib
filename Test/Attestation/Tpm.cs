using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using fido2_net_lib.Test;
using Fido2NetLib;
using Fido2NetLib.Objects;
using PeterO.Cbor;
using Xunit;

namespace Test.Attestation
{
    public class Tpm : Fido2Tests.Attestation
    {
        public Tpm()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "tpm");
        }

        [Fact]
        public void EC2()
        {
            Fido2Tests._validCOSEParameters.ForEach(delegate (object[] param)
            {
                X509Certificate2 root, attestnCert;
                DateTimeOffset notBefore = DateTimeOffset.UtcNow;
                DateTimeOffset notAfter = notBefore.AddDays(2);
                var rootDN = new X500DistinguishedName("CN=Testing, O=FIDO2-NET-LIB, C=US");
                var attDN = new X500DistinguishedName("");
                var oidIdFidoGenCeAaguid = new Oid("1.3.6.1.4.1.45724.1.1.4");
                var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x30, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x02, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
                var asnEncodedAaguid = new byte[] { 0x04, 0x10, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
                (Fido2.CredentialMakeResult, AssertionVerificationResult) res = (null, null);

                switch ((COSE.KeyType)param[0])
                {
                    case COSE.KeyType.EC2:
                        using (var ecdsaRoot = ECDsa.Create())
                        {
                            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                            rootRequest.CertificateExtensions.Add(
                                new X509BasicConstraintsExtension(true, true, 2, false));

                            ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

                            var curve = (COSE.EllipticCurve)param[2];
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

                                attRequest.CertificateExtensions.Add(
                                    new X509Extension(
                                        "2.5.29.17",
                                        asnEncodedSAN,
                                        false)
                                    );

                                attRequest.CertificateExtensions.Add(
                                    new X509EnhancedKeyUsageExtension(
                                        new OidCollection
                                        {
                                    new Oid("2.23.133.8.3")
                                        },
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

                                attRequest.CertificateExtensions.Add(
                                    new X509Extension(
                                        "2.5.29.17",
                                        asnEncodedSAN,
                                        false)
                                    );

                                attRequest.CertificateExtensions.Add(
                                    new X509EnhancedKeyUsageExtension(
                                        new OidCollection
                                        {
                                    new Oid("2.23.133.8.3")
                                        },
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

                                res = MakeAttestationResponse(_attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1], rsa: rsaAtt, X5c: X5c).Result;
                            }
                        }

                        break;
                }                
                _attestationObject = CBORObject.NewMap().Add("fmt", "tpm");
            });
        }
    }
}
