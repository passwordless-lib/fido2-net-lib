using System;
using System.Linq;
using System.Runtime.InteropServices;
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
        public void TestSelf()
        {
            Fido2Tests._validCOSEParameters.ForEach(async delegate (object[] param)
            {
                var crv = (param.Length == 3) ? (COSE.EllipticCurve)param[2] : COSE.EllipticCurve.Reserved;

                var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], crv);

                _attestationObject.Set("attStmt", CBORObject.NewMap()
                    .Add("alg", (COSE.Algorithm)param[1])
                    .Add("sig", signature));

                var res = await MakeAttestationResponse();

                Assert.Equal(string.Empty, res.ErrorMessage);
                Assert.Equal("ok", res.Status);
                Assert.Equal(_aaguid, res.Result.Aaguid);
                Assert.Equal(_signCount, res.Result.Counter);
                Assert.Equal("packed", res.Result.CredType);
                Assert.Equal(_credentialID, res.Result.CredentialId);
                Assert.Null(res.Result.ErrorMessage);
                Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
                Assert.Null(res.Result.Status);
                Assert.Equal("Test User", res.Result.User.DisplayName);
                Assert.Equal(System.Text.Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id);
                Assert.Equal("testuser", res.Result.User.Name);
                _attestationObject = CBORObject.NewMap().Add("fmt", "packed");
            });
        }
        [Fact]
        public void TestSelfAlgMismatch()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]);

            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", COSE.Algorithm.ES384)
                .Add("sig", signature));

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Algorithm mismatch between credential public key and authenticator data in self attestation statement", ex.Result.Message);
        }
        [Fact]
        public void TestSelfBadSig()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]);
            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", (COSE.Algorithm)param[1])
                .Add("sig", new byte[] { 0x30, 0x45, 0x02, 0x20, 0x11, 0x9b, 0x6f, 0xa8, 0x1c, 0xe1, 0x75, 0x9e, 0xbe, 0xf1, 0x52, 0xa6, 0x99, 0x40, 0x5e, 0xd6, 0x6a, 0xcc, 0x01, 0x33, 0x65, 0x18, 0x05, 0x00, 0x96, 0x28, 0x29, 0xbe, 0x85, 0x57, 0xb7, 0x1d, 0x02, 0x21, 0x00, 0x94, 0x50, 0x1d, 0xf1, 0x90, 0x03, 0xa4, 0x4d, 0xa4, 0xdf, 0x9f, 0xbb, 0xb5, 0xe4, 0xce, 0x91, 0x6b, 0xc3, 0x90, 0xe8, 0x38, 0x99, 0x66, 0x4f, 0xa5, 0xc4, 0x0c, 0xf3, 0xed, 0xe3, 0xda, 0x83 }));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Failed to validate signature", ex.Result.Message);
        }

        [Fact]
        public void TestMissingAlg()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]);
            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("sig", signature));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid packed attestation algorithm", ex.Result.Message);
        }

        [Fact]
        public void TestAlgNaN()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]);
            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", "invalid alg")
                .Add("sig", signature));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid packed attestation algorithm", ex.Result.Message);
        }

        [Fact]
        public void TestSigNull()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]);
            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", (COSE.Algorithm)param[1])
                .Add("sig", null));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid packed attestation signature", ex.Result.Message);
        }

        [Fact]
        public void TestSigNotByteString()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]);
            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", (COSE.Algorithm)param[1])
                .Add("sig", "walrus"));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid packed attestation signature", ex.Result.Message);
        }

        [Fact]
        public void TestSigByteStringZeroLen()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]);
            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", (COSE.Algorithm)param[1])
                .Add("sig", CBORObject.FromObject(new byte[0])));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid packed attestation signature", ex.Result.Message);
        }

        [Fact]
        public void TestFull()
        {
            Fido2Tests._validCOSEParameters.ForEach(async delegate (object[] param)
            {
                if (COSE.KeyType.OKP == (COSE.KeyType)param[0])
                {
                    return;
                }
                X509Certificate2 root, attestnCert;
                DateTimeOffset notBefore = DateTimeOffset.UtcNow;
                DateTimeOffset notAfter = notBefore.AddDays(2);
                var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

                Fido2.CredentialMakeResult res = null;

                switch ((COSE.KeyType)param[0])
                {
                    case COSE.KeyType.EC2:
                        using (var ecdsaRoot = ECDsa.Create())
                        {
                            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                            rootRequest.CertificateExtensions.Add(caExt);

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
                                case COSE.EllipticCurve.P256K:
                                    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                                    {
                                        // see https://github.com/dotnet/runtime/issues/47770
                                        throw new PlatformNotSupportedException($"No support currently for secP256k1 on MacOS");
                                    }
                                    eCCurve = ECCurve.CreateFromFriendlyName("secP256k1");
                                    break;
                            }

                            using (root = rootRequest.CreateSelfSigned(
                                notBefore,
                                notAfter))

                            using (var ecdsaAtt = ECDsa.Create(eCCurve))
                            {
                                var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                                attRequest.CertificateExtensions.Add(notCAExt);

                                attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                                var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                                _attestationObject.Set("attStmt", CBORObject.NewMap()
                                    .Add("alg", (COSE.Algorithm)param[1])
                                    .Add("sig", signature)
                                    .Add("x5c", X5c));

                                res = await MakeAttestationResponse();
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
                            rootRequest.CertificateExtensions.Add(caExt);

                            using (root = rootRequest.CreateSelfSigned(
                                notBefore,
                                notAfter))

                            using (var rsaAtt = RSA.Create())
                            {
                                var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                                attRequest.CertificateExtensions.Add(notCAExt);

                                attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                                var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], COSE.EllipticCurve.Reserved, rsa: rsaAtt);

                                _attestationObject.Set("attStmt", CBORObject.NewMap()
                                    .Add("alg", (COSE.Algorithm)param[1])
                                    .Add("sig", signature)
                                    .Add("x5c", X5c));

                                res = await MakeAttestationResponse();
                            }
                        }
                        break;
                    case COSE.KeyType.OKP:
                        {
                            var avr = new AssertionVerificationResult()
                            {
                                CredentialId = new byte[] { 0xf1, 0xd0 },
                                ErrorMessage = string.Empty,
                                Status = "ok",
                            };
                        }
                        break;
                }
                Assert.Equal(string.Empty, res.ErrorMessage);
                Assert.Equal("ok", res.Status);
                Assert.Equal(_aaguid, res.Result.Aaguid);
                Assert.Equal(_signCount, res.Result.Counter);
                Assert.Equal("packed", res.Result.CredType);
                Assert.Equal(_credentialID, res.Result.CredentialId);
                Assert.Null(res.Result.ErrorMessage);
                Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
                Assert.Null(res.Result.Status);
                Assert.Equal("Test User", res.Result.User.DisplayName);
                Assert.Equal(System.Text.Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id);
                Assert.Equal("testuser", res.Result.User.Name);
                _attestationObject = CBORObject.NewMap().Add("fmt", "packed");
            });
        }

        [Fact]
        public void TestFullMissingX5c()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", null));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Malformed x5c array in packed attestation statement", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestFullX5cNotArray()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", "boomerang"));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Malformed x5c array in packed attestation statement", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestFullX5cCountNotOne()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], COSE.EllipticCurve.Reserved, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0])).Add(CBORObject.FromObject(new byte[0]))));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Malformed x5c cert found in packed attestation statement", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestFullX5cValueNotByteString()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], COSE.EllipticCurve.Reserved, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", "x".ToArray()));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Malformed x5c cert found in packed attestation statement", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestFullX5cValueZeroLengthByteString()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0]))));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Malformed x5c cert found in packed attestation statement", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestFullX5cCertExpired()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-7);
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Packed signing certificate expired or not yet valid", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestFullX5cCertNotYetValid()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(1);
            DateTimeOffset notAfter = notBefore.AddDays(7);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Packed signing certificate expired or not yet valid", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestFullInvalidAlg()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", 42)
                        .Add("sig", signature)
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<InvalidOperationException>(() => MakeAttestationResponse());
                    Assert.Equal("Missing or unknown alg 42", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestFullInvalidSig()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", new byte[] { 0x30, 0x45, 0x02, 0x20, 0x11, 0x9b, 0x6f, 0xa8, 0x1c, 0xe1, 0x75, 0x9e, 0xbe, 0xf1, 0x52, 0xa6, 0x99, 0x40, 0x5e, 0xd6, 0x6a, 0xcc, 0x01, 0x33, 0x65, 0x18, 0x05, 0x00, 0x96, 0x28, 0x29, 0xbe, 0x85, 0x57, 0xb7, 0x1d, 0x02, 0x21, 0x00, 0x94, 0x50, 0x1d, 0xf1, 0x90, 0x03, 0xa4, 0x4d, 0xa4, 0xdf, 0x9f, 0xbb, 0xb5, 0xe4, 0xce, 0x91, 0x6b, 0xc3, 0x90, 0xe8, 0x38, 0x99, 0x66, 0x4f, 0xa5, 0xc4, 0x0c, 0xf3, 0xed, 0xe3, 0xda, 0x83 })
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Invalid full packed signature", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestFullAttCertNotV3()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var rawAttestnCert = attestnCert.RawData;
                    rawAttestnCert[12] = 0x41;

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(rawAttestnCert))
                        .Add(CBORObject.FromObject(root.RawData));

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", X5c));

                    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        // Actually throws Interop.AppleCrypto.AppleCommonCryptoCryptographicException
                        var ex = Assert.ThrowsAnyAsync<CryptographicException>(() => MakeAttestationResponse());
                        Assert.Equal("Unknown format in import.", ex.Result.Message);
                    }

                    else
                    {
                        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                        Assert.Equal("Packed x5c attestation certificate not V3", ex.Result.Message);
                    }
                }
            }
        }

        [Fact]
        public void TestFullAttCertSubject()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Not Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Invalid attestation cert subject", ex.Result.Message);
                }
            }
        }

        [Fact]
        public async void TestAttCertSubjectCommaAsync()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=\"FIDO2-NET-LIB, Inc.\", C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", X5c));

                    var res = await MakeAttestationResponse();
                    Assert.Equal(string.Empty, res.ErrorMessage);
                    Assert.Equal("ok", res.Status);
                }
            }
        }

        [Fact]
        public void TestFullAttCertAaguidNotMatchAuthdata()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    var notAsnEncodedAaguid = _asnEncodedAaguid;
                    notAsnEncodedAaguid[3] = 0x42;
                    var notIdFidoGenCeAaguidExt = new X509Extension(oidIdFidoGenCeAaguid, _asnEncodedAaguid, false);
                    attRequest.CertificateExtensions.Add(notIdFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("aaguid present in packed attestation cert exts but does not match aaguid from authData", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestFullAttCertCAFlagSet()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(caExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

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

                    var signature = SignData((COSE.KeyType)param[0], (COSE.Algorithm)param[1], curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", (COSE.Algorithm)param[1])
                        .Add("sig", signature)
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Attestation certificate has CA cert flag present", ex.Result.Message);
                }
            }
        }
    }
}
