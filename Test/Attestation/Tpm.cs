using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using fido2_net_lib.Test;
using Fido2NetLib;
using Fido2NetLib.Objects;
using PeterO.Cbor;
using Xunit;
using Fido2NetLib.AttestationFormat;
using Asn1;
using System.Runtime.InteropServices;

namespace Test.Attestation
{
    public class Tpm : Fido2Tests.Attestation
    {
        private X500DistinguishedName attDN = new X500DistinguishedName("");
        private X509Certificate2 rootCert, attestnCert;
        private DateTimeOffset notBefore, notAfter;
        private X509EnhancedKeyUsageExtension tcgKpAIKCertExt;
        private X509Extension aikCertSanExt;
        private IEnumerable<byte> unique, exponent, curveId, kdf;
        private byte[] type, tpmAlg;

        public Tpm()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "tpm");
            unique = null;
            exponent = null;
            curveId = null;
            kdf = null;
            type = new byte[2];
            tpmAlg = new byte[2];

            notBefore = DateTimeOffset.UtcNow;
            notAfter = notBefore.AddDays(2);
            caExt = new X509BasicConstraintsExtension(true, true, 2, false);
            notCAExt = new X509BasicConstraintsExtension(false, false, 0, false);
            tcgKpAIKCertExt = new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new Oid("2.23.133.8.3")
                },
                false);


            var tpmManufacturer = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { AsnElt.MakeOID("2.23.133.2.1"), AsnElt.MakeString(AsnElt.UTF8String, "id:FFFFF1D0") });
            var tpmModel = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { AsnElt.MakeOID("2.23.133.2.2"), AsnElt.MakeString(AsnElt.UTF8String, "FIDO2-NET-LIB-TEST-TPM") });
            var tpmVersion = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { AsnElt.MakeOID("2.23.133.2.3"), AsnElt.MakeString(AsnElt.UTF8String, "id:F1D00002") });
            var tpmDeviceAttributes = AsnElt.Make(AsnElt.SET, new AsnElt[] { tpmManufacturer, tpmModel, tpmVersion });
            var tpmDirectoryName = AsnElt.Make(AsnElt.SEQUENCE, tpmDeviceAttributes);
            var tpmGeneralName = AsnElt.MakeExplicit(AsnElt.OCTET_STRING, tpmDirectoryName);
            var tpmSAN = AsnElt.Make(AsnElt.SEQUENCE, tpmGeneralName);
            var asnEncodedSAN = tpmSAN.Encode();

            aikCertSanExt = new X509Extension(
                "2.5.29.17",
                asnEncodedSAN,
                false);
        }

        [Fact]
        public void TestTPM()
        {
            Fido2Tests._validCOSEParameters.ForEach(async delegate (object[] param)
            {
                if (COSE.KeyType.OKP == (COSE.KeyType)param[0])
                {
                    return;
                }

                var alg = (COSE.Algorithm)param[1];
                if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                    tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
                if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                    tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
                if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                    tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
                if (alg == COSE.Algorithm.RS1)
                    tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

                switch ((COSE.KeyType)param[0])
                {
                    case COSE.KeyType.EC2:
                        using (var ecdsaRoot = ECDsa.Create())
                        {
                            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                            rootRequest.CertificateExtensions.Add(caExt);

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

                            using (rootCert = rootRequest.CreateSelfSigned(
                                notBefore,
                                notAfter))

                            using (var ecdsaAtt = ECDsa.Create(eCCurve))
                            {
                                var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                                attRequest.CertificateExtensions.Add(notCAExt);

                                attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                                attRequest.CertificateExtensions.Add(aikCertSanExt);

                                attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                                byte[] serial = new byte[12];

                                using (var rng = RandomNumberGenerator.Create())
                                {
                                    rng.GetBytes(serial);
                                }
                                using (X509Certificate2 publicOnly = attRequest.Create(
                                    rootCert,
                                    notBefore,
                                    notAfter,
                                    serial))
                                {
                                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                                }

                                var X5c = CBORObject.NewArray()
                                    .Add(CBORObject.FromObject(attestnCert.RawData))
                                    .Add(CBORObject.FromObject(rootCert.RawData));

                                var ecparams = ecdsaAtt.ExportParameters(true);

                                var cpk = CBORObject.NewMap();
                                cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                                cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                                cpk.Add(COSE.KeyTypeParameter.X, ecparams.Q.X);
                                cpk.Add(COSE.KeyTypeParameter.Y, ecparams.Q.Y);
                                cpk.Add(COSE.KeyTypeParameter.Crv, (COSE.EllipticCurve)param[2]);

                                var x = cpk[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString();
                                var y = cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString();

                                _credentialPublicKey = new CredentialPublicKey(cpk);

                                unique = BitConverter
                                    .GetBytes((UInt16)x.Length)
                                    .Reverse()
                                    .ToArray()
                                    .Concat(x)
                                    .Concat(BitConverter.GetBytes((UInt16)y.Length)
                                                        .Reverse()
                                                        .ToArray())
                                    .Concat(y);

                                var CoseCurveToTpm = new Dictionary<int, TpmEccCurve>
                                {
                                    { 1, TpmEccCurve.TPM_ECC_NIST_P256},
                                    { 2, TpmEccCurve.TPM_ECC_NIST_P384},
                                    { 3, TpmEccCurve.TPM_ECC_NIST_P521},
                                };

                                curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Crv)].AsInt32()]).Reverse().ToArray();
                                kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);
                                type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_ECC).Reverse().ToArray();

                                var pubArea = CreatePubArea(
                                    type, // Type
                                    tpmAlg, // Alg
                                    new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                                    new byte[] { 0x00 }, // Policy
                                    new byte[] { 0x00, 0x10 }, // Symmetric
                                    new byte[] { 0x00, 0x10 }, // Scheme
                                    new byte[] { 0x80, 0x00 }, // KeyBits
                                    exponent?.ToArray(), // Exponent
                                    curveId?.ToArray(), // CurveID
                                    kdf?.ToArray(), // KDF
                                    unique.ToArray() // Unique
                                );
                                
                                var hashAlg = CryptoUtils.algMap[(int)alg];
                                byte[] hashedData = _attToBeSignedHash(hashAlg);
                                
                                byte[] hashedPubArea;
                                using (var hasher = CryptoUtils.GetHasher(hashAlg))
                                {
                                    hashedPubArea = hasher.ComputeHash(pubArea);
                                }

                                IEnumerable<byte> extraData = BitConverter
                                    .GetBytes((UInt16)hashedData.Length)
                                    .Reverse()
                                    .ToArray()
                                    .Concat(hashedData);

                                var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                                {
                                    {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                                    {TpmAlg.TPM_ALG_SHA256, (256/8) },
                                    {TpmAlg.TPM_ALG_SHA384, (384/8) },
                                    {TpmAlg.TPM_ALG_SHA512, (512/8) }
                                };

                                var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                                IEnumerable<byte> tpm2bName = new byte[] { }
                                    .Concat(tpm2bNameLen)
                                    .Concat(tpmAlg)
                                    .Concat(hashedPubArea);

                                var certInfo = CreateCertInfo(
                                        new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                                        new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                                        new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                                        extraData.ToArray(), // ExtraData
                                        new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                                        new byte[] { 0x00 }, // Safe
                                        new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                                        tpm2bName.ToArray(), // TPM2BName
                                        new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                                    );

                                byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, ecdsaAtt, null, null);

                                _attestationObject.Add("attStmt", CBORObject.NewMap()
                                    .Add("ver", "2.0")
                                    .Add("alg", alg)
                                    .Add("x5c", X5c)
                                    .Add("sig", signature)
                                    .Add("certInfo", certInfo)
                                    .Add("pubArea", pubArea));
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

                            using (rootCert = rootRequest.CreateSelfSigned(
                                notBefore,
                                notAfter))

                            using (var rsaAtt = RSA.Create())
                            {
                                var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);
                                
                                attRequest.CertificateExtensions.Add(notCAExt);

                                attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                                attRequest.CertificateExtensions.Add(aikCertSanExt);

                                attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                                byte[] serial = new byte[12];

                                using (var rng = RandomNumberGenerator.Create())
                                {
                                    rng.GetBytes(serial);
                                }
                                using (X509Certificate2 publicOnly = attRequest.Create(
                                    rootCert,
                                    notBefore,
                                    notAfter,
                                    serial))
                                {
                                    attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                                }

                                var X5c = CBORObject.NewArray()
                                    .Add(CBORObject.FromObject(attestnCert.RawData))
                                    .Add(CBORObject.FromObject(rootCert.RawData));
                                var rsaparams = rsaAtt.ExportParameters(true);

                                var cpk = CBORObject.NewMap();
                                cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                                cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                                cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                                cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                                _credentialPublicKey = new CredentialPublicKey(cpk);


                                unique = rsaparams.Modulus;
                                exponent = rsaparams.Exponent;
                                type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                                var pubArea = CreatePubArea(
                                    type, // Type
                                    tpmAlg, // Alg
                                    new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                                    new byte[] { 0x00 }, // Policy
                                    new byte[] { 0x00, 0x10 }, // Symmetric
                                    new byte[] { 0x00, 0x10 }, // Scheme
                                    new byte[] { 0x80, 0x00 }, // KeyBits
                                    exponent?.ToArray(), // Exponent
                                    curveId?.ToArray(), // CurveID
                                    kdf?.ToArray(), // KDF
                                    unique.ToArray() // Unique
                                );

                                byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                                Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                                Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                                byte[] hashedData;
                                byte[] hashedPubArea;
                                var hashAlg = CryptoUtils.algMap[(int)alg];
                                using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                                {
                                    hashedData = hasher.ComputeHash(data);
                                    hashedPubArea = hasher.ComputeHash(pubArea);
                                }
                                IEnumerable<byte> extraData = BitConverter
                                    .GetBytes((UInt16)hashedData.Length)
                                    .Reverse()
                                    .ToArray()
                                    .Concat(hashedData);

                                var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                                {
                                    {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                                    {TpmAlg.TPM_ALG_SHA256, (256/8) },
                                    {TpmAlg.TPM_ALG_SHA384, (384/8) },
                                    {TpmAlg.TPM_ALG_SHA512, (512/8) }
                                };

                                var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                                IEnumerable<byte> tpm2bName = new byte[] { }
                                    .Concat(tpm2bNameLen)
                                    .Concat(tpmAlg)
                                    .Concat(hashedPubArea);

                                var certInfo = CreateCertInfo(
                                        new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                                        new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                                        new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                                        extraData.ToArray(), // ExtraData
                                        new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                                        new byte[] { 0x00 }, // Safe
                                        new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                                        tpm2bName.ToArray(), // TPM2BName
                                        new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                                    );

                                byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                                _attestationObject.Set("attStmt", CBORObject.NewMap()
                                    .Add("ver", "2.0")
                                    .Add("alg", alg)
                                    .Add("x5c", X5c)
                                    .Add("sig", signature)
                                    .Add("certInfo", certInfo)
                                    .Add("pubArea", pubArea));
                            }
                        }

                        break;
                }
                var res = await MakeAttestationResponse();

                Assert.Equal(string.Empty, res.ErrorMessage);
                Assert.Equal("ok", res.Status);
                Assert.Equal(_aaguid, res.Result.Aaguid);
                Assert.Equal(_signCount, res.Result.Counter);
                Assert.Equal("tpm", res.Result.CredType);
                Assert.Equal(_credentialID, res.Result.CredentialId);
                Assert.Null(res.Result.ErrorMessage);
                Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
                Assert.Null(res.Result.Status);
                Assert.Equal("Test User", res.Result.User.DisplayName);
                Assert.Equal(System.Text.Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id);
                Assert.Equal("testuser", res.Result.User.Name);
                _attestationObject = CBORObject.NewMap().Add("fmt", "tpm");
            });
        }

        [Fact]
        public void TestTPMSigNull()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);


                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", null)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));


                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Invalid TPM attestation signature", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMSigNotByteString()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);


                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", "strawberries")
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Invalid TPM attestation signature", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMSigByteStringZeroLen()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);


                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", CBORObject.FromObject(new byte[0]))
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Invalid TPM attestation signature", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMVersionNot2()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);


                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "3.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("FIDO2 only supports TPM 2.0", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaNull()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", null));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Missing or malformed pubArea", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaNotByteString()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);


                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", "banana"));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Missing or malformed pubArea", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaByteStringZeroLen()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);


                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", CBORObject.FromObject(new byte[0])));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Missing or malformed pubArea", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaUniqueNull()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);


                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();
                    var tpmalg = (TpmAlg)Enum.Parse(typeof(TpmAlg), BitConverter.ToUInt16(type.Reverse().ToArray(), 0).ToString());
                    var policy = new byte[] { 0x00 };
                    var pubArea
                         = type
                        .Concat(tpmAlg)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                        .Concat(BitConverter.GetBytes((UInt16)policy.Length)
                            .Reverse()
                            .ToArray())
                        .Concat(policy)
                        .Concat(new byte[] { 0x00, 0x10 })
                        .Concat(new byte[] { 0x00, 0x10 })
                        .Concat(new byte[] { 0x80, 0x00 })
                        .Concat(BitConverter.GetBytes(exponent.ToArray()[0] + (exponent.ToArray()[1] << 8) + (exponent.ToArray()[2] << 16)));
                   
                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea.ToArray());
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Missing or malformed pubArea", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaUniqueByteStringZeroLen()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);


                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        new byte[0] // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Missing or malformed pubArea", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaUniquePublicKeyMismatch()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);


                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.Reverse().ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Public key mismatch between pubArea and credentialPublicKey", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaUniqueExponentMismatch()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        new byte[] { 0x00, 0x01, 0x00 } , // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Public key exponent mismatch between pubArea and credentialPublicKey", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaUniqueXValueMismatch()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            var alg = (COSE.Algorithm)param[1];
            tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

                var curve = (COSE.EllipticCurve)param[2];

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));

                    var ecparams = ecdsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.X, ecparams.Q.X);
                    cpk.Add(COSE.KeyTypeParameter.Y, ecparams.Q.Y);
                    cpk.Add(COSE.KeyTypeParameter.Crv, (COSE.EllipticCurve)param[2]);

                    var x = cpk[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString().Reverse().ToArray();
                    var y = cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString();

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = BitConverter
                        .GetBytes((UInt16)x.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(x)
                        .Concat(BitConverter.GetBytes((UInt16)y.Length)
                                            .Reverse()
                                            .ToArray())
                        .Concat(y);

                    var CoseCurveToTpm = new Dictionary<int, TpmEccCurve>
                    {
                        { 1, TpmEccCurve.TPM_ECC_NIST_P256},
                        { 2, TpmEccCurve.TPM_ECC_NIST_P384},
                        { 3, TpmEccCurve.TPM_ECC_NIST_P521},
                    };

                    curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Crv)].AsInt32()]).Reverse().ToArray();
                    kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_ECC).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, ecdsaAtt, null, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("X-coordinate mismatch between pubArea and credentialPublicKey", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaUniqueYValueMismatch()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            var alg = (COSE.Algorithm)param[1];
            tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

                var curve = (COSE.EllipticCurve)param[2];

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));

                    var ecparams = ecdsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.X, ecparams.Q.X);
                    cpk.Add(COSE.KeyTypeParameter.Y, ecparams.Q.Y);
                    cpk.Add(COSE.KeyTypeParameter.Crv, (COSE.EllipticCurve)param[2]);

                    var x = cpk[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString();
                    var y = cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString().Reverse().ToArray();

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = BitConverter
                        .GetBytes((UInt16)x.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(x)
                        .Concat(BitConverter.GetBytes((UInt16)y.Length)
                                            .Reverse()
                                            .ToArray())
                        .Concat(y);

                    var CoseCurveToTpm = new Dictionary<int, TpmEccCurve>
                                {
                                    { 1, TpmEccCurve.TPM_ECC_NIST_P256},
                                    { 2, TpmEccCurve.TPM_ECC_NIST_P384},
                                    { 3, TpmEccCurve.TPM_ECC_NIST_P521},
                                };

                    curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Crv)].AsInt32()]).Reverse().ToArray();
                    kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_ECC).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, ecdsaAtt, null, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Y-coordinate mismatch between pubArea and credentialPublicKey", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaUniqueCurveMismatch()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            var alg = (COSE.Algorithm)param[1];
            tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

                var curve = (COSE.EllipticCurve)param[2];

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));

                    var ecparams = ecdsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.X, ecparams.Q.X);
                    cpk.Add(COSE.KeyTypeParameter.Y, ecparams.Q.Y);
                    cpk.Add(COSE.KeyTypeParameter.Crv, (COSE.EllipticCurve)param[2]);

                    var x = cpk[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString();
                    var y = cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString();

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = BitConverter
                        .GetBytes((UInt16)x.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(x)
                        .Concat(BitConverter.GetBytes((UInt16)y.Length)
                                            .Reverse()
                                            .ToArray())
                        .Concat(y);

                    var CoseCurveToTpm = new Dictionary<int, TpmEccCurve>
                    {
                        { 1, TpmEccCurve.TPM_ECC_NIST_P256},
                        { 2, TpmEccCurve.TPM_ECC_NIST_P384},
                        { 3, TpmEccCurve.TPM_ECC_NIST_P521},
                    };

                    curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[2]).Reverse().ToArray();
                    kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_ECC).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, ecdsaAtt, null, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Curve mismatch between pubArea and credentialPublicKey", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoNull()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", null)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("CertInfo invalid parsing TPM format attStmt", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoNotByteString()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", "tomato")
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("CertInfo invalid parsing TPM format attStmt", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoByteStringZeroLen()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", CBORObject.FromObject(new byte[0]))
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("CertInfo invalid parsing TPM format attStmt", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoBadMagic()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }, // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Bad magic number 474354FF", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoBadType()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }, // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Bad structure tag 1780", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoExtraDataZeroLen()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)0)
                        .Reverse()
                        .ToArray();

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            new byte[0], // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Bad extraData in certInfo", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoTPM2BNameIsHandle()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(new byte[] { 0x00, 0x04 })
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Unexpected handle in TPM2B_NAME", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoTPM2BNoName()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(new byte[] { 0x00, 0x00 })
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Unexpected no name found in TPM2B_NAME", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoTPM2BExtraBytes()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length + 1)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea)
                        .Concat(new byte[] { 0x00 });

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Unexpected extra bytes found in TPM2B_NAME", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoTPM2BInvalidHashAlg()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(new byte[] { 0x00, 0x10 })
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("TPM_ALG_ID found in TPM2B_NAME not acceptable hash algorithm", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMCertInfoTPM2BInvalidTPMALGID()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(new byte[] { 0xff, 0xff })
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Invalid TPM_ALG_ID found in TPM2B_NAME", ex.Result.Message);
                }
            }
        }


        [Fact]
        public void TestTPMAlgNull()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", null)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Invalid TPM attestation algorithm", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAlgNotNumber()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", "kiwi")
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Invalid TPM attestation algorithm", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAlgInvalid()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", 0)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Invalid TPM attestation algorithm", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAlgMismatch()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", COSE.Algorithm.RS1)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Hash value mismatch extraData and attToBeSigned", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMPubAreaAttestedDataMismatch()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();


                    hashedPubArea[hashedPubArea.Length - 1] ^= 0xFF;

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);
                    
                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Hash value mismatch attested and pubArea", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMMissingX5c()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", null)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Neither x5c nor ECDAA were found in the TPM attestation statement", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestX5cNotArray()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", "string")
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Neither x5c nor ECDAA were found in the TPM attestation statement", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMX5cCountZero()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", CBORObject.NewArray())
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Neither x5c nor ECDAA were found in the TPM attestation statement", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMX5cValuesNull()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", CBORObject.NewArray().Add(null))
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Malformed x5c in TPM attestation", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMX5cValuesCountZero()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", CBORObject.NewArray().Add(CBORObject.Null))
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Malformed x5c in TPM attestation", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMFirstX5cValueNotByteString()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", "x".ToArray())
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Malformed x5c in TPM attestation", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMFirstX5cValueByteStringZeroLen()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0])))
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Malformed x5c in TPM attestation", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMBadSignature()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);
                    signature[signature.Length - 1] ^= 0xff;

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Bad signature in TPM with aikCert", ex.Result.Message);
                }
            }
        }

        [Fact]        
        public void TestTPMAikCertNotV3()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var rawAttestnCert = attestnCert.RawData;
                    rawAttestnCert[12] = 0x41;

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(rawAttestnCert))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));

                    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        // Actually throws Interop.AppleCrypto.AppleCommonCryptoCryptographicException
                        var ex = Assert.ThrowsAnyAsync<CryptographicException>(() => MakeAttestationResponse());
                        Assert.Equal("Unknown format in import.", ex.Result.Message);
                    }

                    else
                    {
                        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                        Assert.Equal("aikCert must be V3", ex.Result.Message);
                    }
                }
            }
        }

        [Fact]
        public void TestTPMAikCertSubjectNotEmpty()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attDN = new X500DistinguishedName("CN=Testing, OU=Not Authenticator Attestation, O=FIDO2-NET-LIB, C=US");
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("aikCert subject must be empty", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAikCertSANMissing()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    //attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("SAN missing from TPM attestation certificate", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAikCertSANZeroLen()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    var aikCertSanExt = new X509Extension(
                        "2.5.29.17",
                        new byte[0],
                        false);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("SAN missing from TPM attestation certificate", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAikCertSANNoManufacturer()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x04, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x30, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x02, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
                    var aikCertSanExt = new X509Extension(
                        "2.5.29.17",
                        asnEncodedSAN,
                        false);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAikCertSANNoModel()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x30, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x05, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
                    var aikCertSanExt = new X509Extension(
                        "2.5.29.17",
                        asnEncodedSAN,
                        false);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAikCertSANNoVersion()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x30, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x06, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
                    var aikCertSanExt = new X509Extension(
                        "2.5.29.17",
                        asnEncodedSAN,
                        false);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAikCertSANInvalidManufacturer()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x32, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x02, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
                    var aikCertSanExt = new X509Extension(
                        "2.5.29.17",
                        asnEncodedSAN,
                        false);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("Invalid TPM manufacturer found parsing TPM attestation", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAikCertEKUMissingTCGKP()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    //attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("aikCert EKU missing tcg-kp-AIKCertificate OID", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMAikCertCATrue()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(caExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("aikCert Basic Constraints extension CA component must be false", ex.Result.Message);
                }
            }
        }

        [Fact]
        public async void TestTPMAikCertMisingAAGUID()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    //attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var res = await MakeAttestationResponse();

                    Assert.Equal(string.Empty, res.ErrorMessage);
                    Assert.Equal("ok", res.Status);
                    Assert.Equal(_aaguid, res.Result.Aaguid);
                    Assert.Equal(_signCount, res.Result.Counter);
                    Assert.Equal("tpm", res.Result.CredType);
                    Assert.Equal(_credentialID, res.Result.CredentialId);
                    Assert.Null(res.Result.ErrorMessage);
                    Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
                    Assert.Null(res.Result.Status);
                    Assert.Equal("Test User", res.Result.User.DisplayName);
                    Assert.Equal(System.Text.Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id);
                    Assert.Equal("testuser", res.Result.User.Name);
                }
            }
        }

        [Fact]
        public void TestTPMAikCertAAGUIDNotMatchAuthData()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    var asnEncodedAaguid = new byte[] { 0x04, 0x10, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
                    var idFidoGenCeAaguidExt = new X509Extension(oidIdFidoGenCeAaguid, asnEncodedAaguid, false);
                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("x5c", X5c)
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("aaguid malformed, expected f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0, got d0f1d0f1-d0f1-d0f1-f1d0-f1d0f1d0f1d0", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestTPMECDAANotSupported()
        {
            var param = Fido2Tests._validCOSEParameters[3];

            var alg = (COSE.Algorithm)param[1];
            if (alg == COSE.Algorithm.ES256 || alg == COSE.Algorithm.PS256 || alg == COSE.Algorithm.RS256)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA256).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES384 || alg == COSE.Algorithm.PS384 || alg == COSE.Algorithm.RS384)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA384).Reverse().ToArray();
            if (alg == COSE.Algorithm.ES512 || alg == COSE.Algorithm.PS512 || alg == COSE.Algorithm.RS512)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA512).Reverse().ToArray();
            if (alg == COSE.Algorithm.RS1)
                tpmAlg = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_SHA1).Reverse().ToArray();

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

                using (rootCert = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

                    attRequest.CertificateExtensions.Add(aikCertSanExt);

                    attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        rootCert,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(rootCert.RawData));
                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    unique = rsaparams.Modulus;
                    exponent = rsaparams.Exponent;
                    type = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_RSA).Reverse().ToArray();

                    var pubArea = CreatePubArea(
                        type, // Type
                        tpmAlg, // Alg
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                        new byte[] { 0x00 }, // Policy
                        new byte[] { 0x00, 0x10 }, // Symmetric
                        new byte[] { 0x00, 0x10 }, // Scheme
                        new byte[] { 0x80, 0x00 }, // KeyBits
                        exponent?.ToArray(), // Exponent
                        curveId?.ToArray(), // CurveID
                        kdf?.ToArray(), // KDF
                        unique.ToArray() // Unique
                    );

                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);

                    byte[] hashedData;
                    byte[] hashedPubArea;
                    var hashAlg = CryptoUtils.algMap[(int)alg];
                    using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                    {
                        hashedData = hasher.ComputeHash(data);
                        hashedPubArea = hasher.ComputeHash(pubArea);
                    }
                    IEnumerable<byte> extraData = BitConverter
                        .GetBytes((UInt16)hashedData.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(hashedData);

                    var tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
                    {
                        {TpmAlg.TPM_ALG_SHA1,   (160/8) },
                        {TpmAlg.TPM_ALG_SHA256, (256/8) },
                        {TpmAlg.TPM_ALG_SHA384, (384/8) },
                        {TpmAlg.TPM_ALG_SHA512, (512/8) }
                    };

                    var tpm2bNameLen = BitConverter.GetBytes((UInt16)(tpmAlg.Length + hashedPubArea.Length)).Reverse().ToArray();

                    IEnumerable<byte> tpm2bName = new byte[] { }
                        .Concat(tpm2bNameLen)
                        .Concat(tpmAlg)
                        .Concat(hashedPubArea);

                    var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData.ToArray(), // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName.ToArray(), // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                    byte[] signature = Fido2Tests.SignData((COSE.KeyType)param[0], alg, certInfo, null, rsaAtt, null);

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "2.0")
                        .Add("alg", alg)
                        .Add("ecdaaKeyId", new byte[0])
                        .Add("sig", signature)
                        .Add("certInfo", certInfo)
                        .Add("pubArea", pubArea));
                    

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
                    Assert.Equal("ECDAA support for TPM attestation is not yet implemented", ex.Result.Message);
                }
            }
        }
        
        internal static byte[] CreatePubArea(byte[] type, byte[] alg, byte[] attributes, byte[] policy, byte[] symmetric,
            byte[] scheme, byte[] keyBits, byte[] exponent, byte[] curveID, byte[] kdf, byte[] unique)
        {
            var tpmalg = (TpmAlg)Enum.Parse(typeof(TpmAlg), BitConverter.ToUInt16(type.Reverse().ToArray(), 0).ToString());

            IEnumerable<byte> raw = null;
            var uniqueLen = BitConverter.GetBytes((UInt16)unique.Length).Reverse().ToArray();

            if (TpmAlg.TPM_ALG_RSA == tpmalg)
            {
                raw
                     = type
                    .Concat(alg)
                    .Concat(attributes)
                    .Concat(BitConverter.GetBytes((UInt16)policy.Length)
                        .Reverse()
                        .ToArray())
                    .Concat(policy)
                    .Concat(symmetric)
                    .Concat(scheme)
                    .Concat(keyBits)
                    .Concat(BitConverter.GetBytes(exponent[0] + (exponent[1] << 8) + (exponent[2] << 16)))
                    .Concat(BitConverter.GetBytes((UInt16)unique.Length)
                        .Reverse()
                        .ToArray())
                    .Concat(unique);
            }
            if (TpmAlg.TPM_ALG_ECC == tpmalg)
            {
                raw = type
                    .Concat(alg)
                    .Concat(attributes)
                    .Concat(BitConverter.GetBytes((UInt16)policy.Length)
                        .Reverse()
                        .ToArray())
                    .Concat(policy)
                    .Concat(symmetric)
                    .Concat(scheme)
                    .Concat(curveID)
                    .Concat(kdf)
                    .Concat(BitConverter.GetBytes((UInt16)unique.Length)
                        .Reverse()
                        .ToArray())
                    .Concat(unique);
            }

            return raw.ToArray();
        }

        internal static byte[] CreateCertInfo(byte[] magic, byte[] type, byte[] qualifiedSigner,
            byte[] extraData, byte[] clock, byte[] resetCount, byte[] restartCount,
            byte[] safe, byte[] firmwareRevision, byte[] tPM2BName, byte[] attestedQualifiedNameBuffer)
        {
            IEnumerable<byte> raw = magic
                .Concat(type)
                .Concat(qualifiedSigner)
                .Concat(extraData)
                .Concat(clock)
                .Concat(resetCount)
                .Concat(restartCount)
                .Concat(safe)
                .Concat(firmwareRevision)
                .Concat(tPM2BName)
                .Concat(attestedQualifiedNameBuffer);

            return raw.ToArray();
        }
    }
}
