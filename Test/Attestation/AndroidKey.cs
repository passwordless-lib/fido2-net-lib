using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using fido2_net_lib.Test;
using Fido2NetLib.Objects;
using PeterO.Cbor;
using Xunit;
using Asn1;
using Fido2NetLib;

namespace Test.Attestation
{
    public class AndroidKey : Fido2Tests.Attestation
    {
        public byte[] EncodeAttestationRecord()
        {
            var attestationVersion = AsnElt.MakeInteger(3);
            var attestationSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var keymasterVersion = AsnElt.MakeInteger(2);
            var keymasterSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var attestationChallenge = AsnElt.MakeBlob(_clientDataHash);
            var uniqueId = AsnElt.MakeBlob(_credentialID);
            var creationDateTime = AsnElt.MakeExplicit(701, AsnElt.MakeInteger(DateTimeOffset.Now.ToUnixTimeSeconds()));
            var softwareEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { creationDateTime });
            var purpose = AsnElt.MakeExplicit(1, AsnElt.MakeSetOf(new AsnElt[] { AsnElt.MakeInteger(2) }));
            var origin = AsnElt.MakeExplicit(702, AsnElt.MakeInteger(0));
            var teeEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { purpose, origin });
            return AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                attestationVersion,
                attestationSecurityLevel,
                keymasterVersion,
                keymasterSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced,
                teeEnforced
            }).Encode();
        }
        public AndroidKey()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "android-key");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", EncodeAttestationRecord(), false));

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c)
                        .Add("sig", signature));
                }
            }
        }
        [Fact]
        public void TestAndroidKey()
        {
            var res = MakeAttestationResponse().Result;
            Assert.Equal(string.Empty, res.ErrorMessage);
            Assert.Equal("ok", res.Status);
            Assert.Equal(_aaguid, res.Result.Aaguid);
            Assert.Equal(_signCount, res.Result.Counter);
            Assert.Equal("android-key", res.Result.CredType);
            Assert.Equal(_credentialID, res.Result.CredentialId);
            Assert.Null(res.Result.ErrorMessage);
            Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
            Assert.Null(res.Result.Status);
            Assert.Equal("Test User", res.Result.User.DisplayName);
            Assert.Equal(Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id);
            Assert.Equal("testuser", res.Result.User.Name);
        }

        [Fact]
        public void TestAndroidKeySigNull()
        {
            _attestationObject["attStmt"].Set("sig", null);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid android-key attestation signature", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeySigNotByteString()
        {
            _attestationObject["attStmt"].Set("sig", "walrus");
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid android-key attestation signature", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeySigByteStringZeroLen()
        {
            _attestationObject["attStmt"].Set("sig", CBORObject.FromObject(new byte[0]));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid android-key attestation signature", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyMissingX5c()
        {
            _attestationObject["attStmt"].Set("x5c", null);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in android-key attestation", ex.Result.Message);
        }
        [Fact]
        public void TestAndroidKeyX5cNotArray()
        {
            _attestationObject["attStmt"].Set("x5c", "boomerang");
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in android-key attestation", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyX5cValueNotByteString()
        {
            _attestationObject["attStmt"].Set("x5c", "x".ToArray());
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in android-key attestation", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyX5cValueZeroLengthByteString()
        {
            _attestationObject["attStmt"].Set("x5c", CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0])));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in android-key attestation", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyInvalidPublicKey()
        {
            var attestnCert = _attestationObject["attStmt"]["x5c"].Values.FirstOrDefault().GetByteString();
            attestnCert[0] ^= 0xff;
            var X5c = CBORObject.NewArray().Add(CBORObject.FromObject(attestnCert));
            _attestationObject["attStmt"].Set("x5c", X5c);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.StartsWith("Failed to extract public key from android key: ", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyMissingAlg()
        {
            _attestationObject["attStmt"].Remove("alg");
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid android key attestation algorithm", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyAlgNull()
        {
            _attestationObject["attStmt"].Set("alg", null);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid android key attestation algorithm", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyAlgNaN()
        {
            _attestationObject["attStmt"].Set("alg", "invalid alg");
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid android key attestation algorithm", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyAlgNotInMap()
        {
            _attestationObject["attStmt"].Set("alg", -1);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid android key attestation algorithm", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeySigNotASN1()
        {
            _attestationObject["attStmt"].Set("sig", CBORObject.FromObject(new byte[] { 0xf1, 0xd0 }));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Failed to decode android key attestation signature from ASN.1 encoded form", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyBadSig()
        {
            var sig = _attestationObject["attStmt"]["sig"].GetByteString();
            sig[sig.Length - 1] ^= 0xff;
            _attestationObject["attStmt"].Set("sig", CBORObject.FromObject(sig));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid android key attestation signature", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyX5cCertMissingAttestationRecordExt()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "android-key");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c)
                        .Add("sig", signature));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Android key attestation certificate contains no AttestationRecord extension", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyX5cCertAttestationRecordExtMalformed()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "android-key");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", new byte[] { 0x0 }, false));

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c)
                        .Add("sig", signature));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed android key AttestationRecord extension verifying android key attestation certificate extension", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyX5cCertAttestationRecordAllApplicationsSoftware()
        {
            var attestationVersion = AsnElt.MakeInteger(3);
            var attestationSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var keymasterVersion = AsnElt.MakeInteger(2);
            var keymasterSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var attestationChallenge = AsnElt.MakeBlob(_clientDataHash);
            var uniqueId = AsnElt.MakeBlob(_credentialID);
            var allApplications = AsnElt.MakeExplicit(600, AsnElt.Make(AsnElt.SEQUENCE, null));
            var creationDateTime = AsnElt.MakeExplicit(701, AsnElt.MakeInteger(DateTimeOffset.Now.ToUnixTimeSeconds()));
            var softwareEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { creationDateTime, allApplications });
            var purpose = AsnElt.MakeExplicit(1, AsnElt.MakeSetOf(new AsnElt[] { AsnElt.MakeInteger(2) }));
            var origin = AsnElt.MakeExplicit(702, AsnElt.MakeInteger(0));
            var teeEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { purpose, origin });
            var attRecord = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                attestationVersion,
                attestationSecurityLevel,
                keymasterVersion,
                keymasterSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced,
                teeEnforced
            }).Encode();

            _attestationObject = CBORObject.NewMap().Add("fmt", "android-key");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c)
                        .Add("sig", signature));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Found all applications field in android key attestation certificate extension", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyX5cCertAttestationRecordAllApplicationsTee()
        {
            var attestationVersion = AsnElt.MakeInteger(3);
            var attestationSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var keymasterVersion = AsnElt.MakeInteger(2);
            var keymasterSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var attestationChallenge = AsnElt.MakeBlob(_clientDataHash);
            var uniqueId = AsnElt.MakeBlob(_credentialID);
            var creationDateTime = AsnElt.MakeExplicit(701, AsnElt.MakeInteger(DateTimeOffset.Now.ToUnixTimeSeconds()));
            var softwareEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { creationDateTime });
            var purpose = AsnElt.MakeExplicit(1, AsnElt.MakeSetOf(new AsnElt[] { AsnElt.MakeInteger(2) }));
            var allApplications = AsnElt.MakeExplicit(600, AsnElt.Make(AsnElt.SEQUENCE, null));
            var origin = AsnElt.MakeExplicit(702, AsnElt.MakeInteger(0));
            var teeEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { purpose, origin, allApplications });
            var attRecord = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                attestationVersion,
                attestationSecurityLevel,
                keymasterVersion,
                keymasterSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced,
                teeEnforced
            }).Encode();

            _attestationObject = CBORObject.NewMap().Add("fmt", "android-key");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c)
                        .Add("sig", signature));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Found all applications field in android key attestation certificate extension", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyX5cCertAttestationRecordOriginSoftware()
        {
            var attestationVersion = AsnElt.MakeInteger(3);
            var attestationSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var keymasterVersion = AsnElt.MakeInteger(2);
            var keymasterSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var attestationChallenge = AsnElt.MakeBlob(_clientDataHash);
            var uniqueId = AsnElt.MakeBlob(_credentialID);
            var creationDateTime = AsnElt.MakeExplicit(701, AsnElt.MakeInteger(DateTimeOffset.Now.ToUnixTimeSeconds()));
            var softwareEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { creationDateTime });
            var purpose = AsnElt.MakeExplicit(1, AsnElt.MakeSetOf(new AsnElt[] { AsnElt.MakeInteger(2) }));
            var origin = AsnElt.MakeExplicit(702, AsnElt.MakeInteger(3));
            var teeEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { purpose, origin });
            var attRecord = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                attestationVersion,
                attestationSecurityLevel,
                keymasterVersion,
                keymasterSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced,
                teeEnforced
            }).Encode();

            _attestationObject = CBORObject.NewMap().Add("fmt", "android-key");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c)
                        .Add("sig", signature));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyX5cCertAttestationRecordOriginTeeTee()
        {
            var attestationVersion = AsnElt.MakeInteger(3);
            var attestationSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var keymasterVersion = AsnElt.MakeInteger(2);
            var keymasterSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var attestationChallenge = AsnElt.MakeBlob(_clientDataHash);
            var uniqueId = AsnElt.MakeBlob(_credentialID);
            var creationDateTime = AsnElt.MakeExplicit(701, AsnElt.MakeInteger(DateTimeOffset.Now.ToUnixTimeSeconds()));
            var origin = AsnElt.MakeExplicit(702, AsnElt.MakeInteger(3));
            var softwareEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { creationDateTime, origin });
            var purpose = AsnElt.MakeExplicit(1, AsnElt.MakeSetOf(new AsnElt[] { AsnElt.MakeInteger(2) }));
            var teeEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { purpose });
            var attRecord = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                attestationVersion,
                attestationSecurityLevel,
                keymasterVersion,
                keymasterSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced,
                teeEnforced
            }).Encode();

            _attestationObject = CBORObject.NewMap().Add("fmt", "android-key");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c)
                        .Add("sig", signature));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyX5cCertAttestationRecordPurposeSoftware()
        {
            var attestationVersion = AsnElt.MakeInteger(3);
            var attestationSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var keymasterVersion = AsnElt.MakeInteger(2);
            var keymasterSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var attestationChallenge = AsnElt.MakeBlob(_clientDataHash);
            var uniqueId = AsnElt.MakeBlob(_credentialID);
            var purpose = AsnElt.MakeExplicit(1, AsnElt.MakeSetOf(new AsnElt[] { AsnElt.MakeInteger(1) }));
            var creationDateTime = AsnElt.MakeExplicit(701, AsnElt.MakeInteger(DateTimeOffset.Now.ToUnixTimeSeconds()));
            var softwareEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { creationDateTime, purpose });
            var origin = AsnElt.MakeExplicit(702, AsnElt.MakeInteger(0));
            var teeEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { origin });
            var attRecord = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                attestationVersion,
                attestationSecurityLevel,
                keymasterVersion,
                keymasterSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced,
                teeEnforced
            }).Encode();

            _attestationObject = CBORObject.NewMap().Add("fmt", "android-key");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c)
                        .Add("sig", signature));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidKeyX5cCertAttestationRecordPurposeTee()
        {
            var attestationVersion = AsnElt.MakeInteger(3);
            var attestationSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var keymasterVersion = AsnElt.MakeInteger(2);
            var keymasterSecurityLevel = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.MakeBlob(new byte[] { 0 }));
            var attestationChallenge = AsnElt.MakeBlob(_clientDataHash);
            var uniqueId = AsnElt.MakeBlob(_credentialID);
            var creationDateTime = AsnElt.MakeExplicit(701, AsnElt.MakeInteger(DateTimeOffset.Now.ToUnixTimeSeconds()));
            var softwareEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { creationDateTime });
            var purpose = AsnElt.MakeExplicit(1, AsnElt.MakeSetOf(new AsnElt[] { AsnElt.MakeInteger(1) }));
            var origin = AsnElt.MakeExplicit(702, AsnElt.MakeInteger(0));
            var teeEnforced = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { purpose, origin });
            var attRecord = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                attestationVersion,
                attestationSecurityLevel,
                keymasterVersion,
                keymasterSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced,
                teeEnforced
            }).Encode();

            _attestationObject = CBORObject.NewMap().Add("fmt", "android-key");
            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c)
                        .Add("sig", signature));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension", ex.Result.Message);
        }
    }
}
