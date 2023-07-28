using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using static Fido2NetLib.DataHelper;

namespace Test.Attestation;

public class Tpm : Fido2Tests.Attestation
{
    private readonly X500DistinguishedName attDN = new ("");
    private X509Certificate2 attestnCert;
    private readonly DateTimeOffset notBefore, notAfter;
    private readonly X509EnhancedKeyUsageExtension tcgKpAIKCertExt;
    private readonly X509Extension aikCertSanExt;
    private byte[] unique, exponent, curveId, kdf;
    private byte[] tpmAlg;

    private static readonly Dictionary<TpmAlg, ushort> TpmAlgToDigestSizeMap = new ()
    {
        { TpmAlg.TPM_ALG_SHA1,   (160/8) },
        { TpmAlg.TPM_ALG_SHA256, (256/8) },
        { TpmAlg.TPM_ALG_SHA384, (384/8) },
        { TpmAlg.TPM_ALG_SHA512, (512/8) }
    };

    private static readonly Dictionary<int, TpmEccCurve> CoseCurveToTpm = new ()
    {
        { 1, TpmEccCurve.TPM_ECC_NIST_P256},
        { 2, TpmEccCurve.TPM_ECC_NIST_P384},
        { 3, TpmEccCurve.TPM_ECC_NIST_P521},
    };

    public Tpm()
    {
        _attestationObject = new CborMap { { "fmt", "tpm" } };
        unique = null;
        exponent = null;
        curveId = null;
        kdf = null;
        var type = new byte[2];
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

        byte[] asnEncodedSAN = TpmSanEncoder.Encode(
            manufacturer : "id:FFFFF1D0", 
            model        : "FIDO2-NET-LIB-TEST-TPM",
            version      : "id:F1D00002"
        );

        aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);
    }

    [Fact]
    public void TestTPM()
    {
        Fido2Tests._validCOSEParameters.ForEach(async ((COSE.KeyType, COSE.Algorithm, COSE.EllipticCurve) param) =>
        {
            var (type, alg, curve) = param;

            if (type is COSE.KeyType.OKP)
            {
                return; // no OKP support in TPM
            }

            if (type is COSE.KeyType.EC2 && alg is COSE.Algorithm.ES256K)
            {
                return; // no secp256k1 support in TPM
            }

            tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

            switch (type)
            {
                case COSE.KeyType.EC2:
                    using (var ecdsaRoot = ECDsa.Create())
                    {
                        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                        rootRequest.CertificateExtensions.Add(caExt);

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

                        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
                        using var ecdsaAtt = ECDsa.Create(eCCurve);
                        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                        attRequest.CertificateExtensions.Add(notCAExt);
                        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
                        attRequest.CertificateExtensions.Add(aikCertSanExt);
                        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                        byte[] serial = RandomNumberGenerator.GetBytes(12);

                        using (X509Certificate2 publicOnly = attRequest.Create(
                            rootCert,
                            notBefore,
                            notAfter,
                            serial))
                        {
                            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                        }

                        var x5c = new CborArray {
                            attestnCert.RawData,
                            rootCert.RawData
                        };

                        var ecparams = ecdsaAtt.ExportParameters(true);

                        var cpk = new CborMap {
                                { COSE.KeyCommonParameter.KeyType, type },
                                { COSE.KeyCommonParameter.Alg, alg},
                                { COSE.KeyTypeParameter.X, ecparams.Q.X},
                                { COSE.KeyTypeParameter.Y, ecparams.Q.Y},
                                { COSE.KeyTypeParameter.Crv, curve},
                            };

                        var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                        var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                        _credentialPublicKey = new CredentialPublicKey(cpk);

                        unique = GetUInt16BigEndianBytes(x.Length)
                            .Concat(x)
                            .Concat(GetUInt16BigEndianBytes(y.Length))
                            .Concat(y)
                            .ToArray();

                        curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[(int)cpk[COSE.KeyTypeParameter.Crv]]).Reverse().ToArray();
                        kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL); // should this be big endian?

                        var pubArea = CreatePubArea(
                            TpmAlg.TPM_ALG_ECC, // Type
                            tpmAlg, // Alg
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                            new byte[] { 0x00 }, // Policy
                            new byte[] { 0x00, 0x10 }, // Symmetric
                            new byte[] { 0x00, 0x10 }, // Scheme
                            new byte[] { 0x80, 0x00 }, // KeyBits
                            exponent, // Exponent
                            curveId, // CurveID
                            kdf, // KDF
                            unique // Unique
                        );

                        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
                        byte[] hashedData = _attToBeSignedHash(hashAlg);
                        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

                        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);

                        var tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);

                        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

                        var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData, // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName, // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, ecdsaAtt, null, null);

                        _attestationObject.Add("attStmt", new CborMap {
                            { "ver", "2.0" },
                            { "alg", alg },
                            { "x5c", x5c },
                            { "sig", signature },
                            { "certInfo", certInfo },
                            { "pubArea", pubArea }
                        });
                    }
                    break;
                case COSE.KeyType.RSA:
                    using (RSA rsaRoot = RSA.Create())
                    {
                        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

                        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
                        rootRequest.CertificateExtensions.Add(caExt);

                        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
                        using var rsaAtt = RSA.Create();
                        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                        attRequest.CertificateExtensions.Add(notCAExt);
                        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
                        attRequest.CertificateExtensions.Add(aikCertSanExt);
                        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                        byte[] serial = RandomNumberGenerator.GetBytes(12);

                        using (X509Certificate2 publicOnly = attRequest.Create(
                            rootCert,
                            notBefore,
                            notAfter,
                            serial))
                        {
                            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                        }

                        var X5c = new CborArray {
                                attestnCert.RawData,
                                rootCert.RawData
                            };

                        var rsaparams = rsaAtt.ExportParameters(true);

                        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

                        unique = rsaparams.Modulus;
                        exponent = rsaparams.Exponent;

                        var pubArea = CreatePubArea(
                            TpmAlg.TPM_ALG_RSA, // Type
                            tpmAlg, // Alg
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                            new byte[] { 0x00 }, // Policy
                            new byte[] { 0x00, 0x10 }, // Symmetric
                            new byte[] { 0x00, 0x10 }, // Scheme
                            new byte[] { 0x80, 0x00 }, // KeyBits
                            exponent, // Exponent
                            curveId, // CurveID
                            kdf, // KDF
                            unique // Unique
                        );

                        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

                        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);

                        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
                        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

                        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
                        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
                        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

                        var certInfo = CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                            extraData, // ExtraData
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                            new byte[] { 0x00 }, // Safe
                            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                            tpm2bName, // TPM2BName
                            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                        );

                        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

                        _attestationObject.Set("attStmt", new CborMap {
                            { "ver", "2.0" },
                            { "alg", alg },
                            { "x5c", X5c },
                            { "sig", signature },
                            { "certInfo", certInfo },
                            { "pubArea", pubArea }
                        });
                    }

                    break;
            }
            var res = await MakeAttestationResponseAsync();

            Assert.Equal(string.Empty, res.ErrorMessage);
            Assert.Equal("ok", res.Status);
            Assert.Equal(_aaguid, res.Result.AaGuid);
            Assert.Equal(_signCount, res.Result.SignCount);
            Assert.Equal("tpm", res.Result.CredType);
            Assert.Equal(_credentialID, res.Result.Id);
            Assert.Null(res.Result.ErrorMessage);
            Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
            Assert.Null(res.Result.Status);
            Assert.Equal("Test User", res.Result.User.DisplayName);
            Assert.Equal("testuser"u8.ToArray(), res.Result.User.Id);
            Assert.Equal("testuser", res.Result.User.Name);
            _attestationObject = new CborMap { { "fmt", "tpm" } };
        });
    }

    [Fact]
    public void TestTPMAikCertSANTCGConformant()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

        byte[] asnEncodedSAN = TpmSanEncoder.Encode(
            manufacturer: "id:FFFFF1D0",
            model: "FIDO2-NET-LIB-TestTPMAikCertSANTCGConformant",
            version: "id:F1D00002"
        );

        var aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);

        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm1bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm1bName = Concat(tpm1bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm1bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var res = MakeAttestationResponseAsync().Result;

        Assert.Equal(string.Empty, res.ErrorMessage);
        Assert.Equal("ok", res.Status);
        Assert.Equal(_aaguid, res.Result.AaGuid);
        Assert.Equal(_signCount, res.Result.SignCount);
        Assert.Equal("tpm", res.Result.CredType);
        Assert.Equal(_credentialID, res.Result.Id);
        Assert.Null(res.Result.ErrorMessage);
        Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
        Assert.Null(res.Result.Status);
        Assert.Equal("Test User", res.Result.User.DisplayName);
        Assert.Equal("testuser"u8.ToArray(), res.Result.User.Id);
        Assert.Equal("testuser", res.Result.User.Name);
    }

    [Fact]
    public void TestTPMSigNull()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", CborNull.Instance },
            { "certInfo", certInfo },
            { "pubArea", pubArea },
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid TPM attestation signature", ex.Result.Message);
    }

    [Fact]
    public void TestTPMSigNotByteString()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);
        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);

        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", X5c },
            { "sig", "strawberries" },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid TPM attestation signature", ex.Result.Message);
    }

    [Fact]
    public void TestTPMSigByteStringZeroLen()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", X5c },
            { "sig", Array.Empty<byte>() },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid TPM attestation signature", ex.Result.Message);
    }

    [Fact]
    public void TestTPMVersionNot2()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        if (alg is COSE.Algorithm.ES256 or COSE.Algorithm.PS256 or COSE.Algorithm.RS256)
            tpmAlg = TpmAlg.TPM_ALG_SHA256.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.ES384 or COSE.Algorithm.PS384 or COSE.Algorithm.RS384)
            tpmAlg = TpmAlg.TPM_ALG_SHA384.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.ES512 or COSE.Algorithm.PS512 or COSE.Algorithm.RS512)
            tpmAlg = TpmAlg.TPM_ALG_SHA512.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.RS1)
            tpmAlg =  TpmAlg.TPM_ALG_SHA1.ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "3.0" },
            { "alg", (int)alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal("FIDO2 only supports TPM 2.0", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaNull()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);

        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo},
            { "pubArea", CborNull.Instance },
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Missing or malformed pubArea", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaNotByteString()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", "banana" }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Missing or malformed pubArea", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaByteStringZeroLen()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", Array.Empty<byte>() }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Missing or malformed pubArea", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaUniqueNull()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;
        var policy = new byte[] { 0x00 };
        var pubArea
             = TpmAlg.TPM_ALG_RSA.ToUInt16BigEndianBytes()
            .Concat(tpmAlg)
            .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
            .Concat(GetUInt16BigEndianBytes(policy.Length))
            .Concat(policy)
            .Concat(new byte[] { 0x00, 0x10 })
            .Concat(new byte[] { 0x00, 0x10 })
            .Concat(new byte[] { 0x80, 0x00 })
            .Concat(BitConverter.GetBytes(exponent[0] + (exponent[1] << 8) + (exponent[2] << 16)))
            .ToArray();

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Missing or malformed pubArea", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaUniqueByteStringZeroLen()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            Array.Empty<byte>() // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);

        var tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);

        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Missing or malformed pubArea", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaUniquePublicKeyMismatch()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique.Reverse().ToArray() // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Public key mismatch between pubArea and credentialPublicKey", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaUniqueExponentMismatch()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            new byte[] { 0x00, 0x01, 0x00 }, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Public key exponent mismatch between pubArea and credentialPublicKey", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaUniqueXValueMismatch()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];

        tpmAlg = TpmAlg.TPM_ALG_SHA256.ToUInt16BigEndianBytes();

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var ecparams = ecdsaAtt.ExportParameters(true);

        var cpk = new CborMap {
            { COSE.KeyCommonParameter.KeyType, type },
            { COSE.KeyCommonParameter.Alg, alg },
            { COSE.KeyTypeParameter.X, ecparams.Q.X },
            { COSE.KeyTypeParameter.Y, ecparams.Q.Y },
            { COSE.KeyTypeParameter.Crv, curve }
        };

        var x = ((byte[])cpk[COSE.KeyTypeParameter.X]).Reverse().ToArray();
        var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

        _credentialPublicKey = new CredentialPublicKey(cpk);

        unique = GetUInt16BigEndianBytes(x.Length)
            .Concat(x)
            .Concat(GetUInt16BigEndianBytes(y.Length))
            .Concat(y)
            .ToArray();

        curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[(int)cpk[COSE.KeyTypeParameter.Crv]]).Reverse().ToArray();
        kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_ECC, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);
        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, ecdsaAtt, null, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", X5c },
            { "sig", signature},
            { "certInfo", certInfo},
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("X-coordinate mismatch between pubArea and credentialPublicKey", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaUniqueYValueMismatch()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];

        tpmAlg = TpmAlg.TPM_ALG_SHA256.ToUInt16BigEndianBytes();

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var ecparams = ecdsaAtt.ExportParameters(true);

        var cpk = new CborMap {
            { COSE.KeyCommonParameter.KeyType, type },
            { COSE.KeyCommonParameter.Alg, alg },
            { COSE.KeyTypeParameter.X, ecparams.Q.X },
            { COSE.KeyTypeParameter.Y, ecparams.Q.Y },
            { COSE.KeyTypeParameter.Crv, curve }
        };

        var x = (byte[])cpk[COSE.KeyTypeParameter.X];
        var y = ((byte[])cpk[COSE.KeyTypeParameter.Y]).Reverse().ToArray();

        _credentialPublicKey = new CredentialPublicKey(cpk);

        unique = GetUInt16BigEndianBytes(x.Length)
            .Concat(x)
            .Concat(GetUInt16BigEndianBytes(y.Length))
            .Concat(y)
            .ToArray();

        curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[(int)cpk[COSE.KeyTypeParameter.Crv]]).Reverse().ToArray();
        kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_ECC, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, ecdsaAtt, null, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Y-coordinate mismatch between pubArea and credentialPublicKey", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaUniqueCurveMismatch()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];

        tpmAlg = TpmAlg.TPM_ALG_SHA256.ToUInt16BigEndianBytes();

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var ecparams = ecdsaAtt.ExportParameters(true);

        var cpk = new CborMap {
            { COSE.KeyCommonParameter.KeyType, type },
            { COSE.KeyCommonParameter.Alg, alg },
            { COSE.KeyTypeParameter.X, ecparams.Q.X },
            { COSE.KeyTypeParameter.Y, ecparams.Q.Y },
            { COSE.KeyTypeParameter.Crv, curve }
        };

        var x = (byte[])cpk[COSE.KeyTypeParameter.X];
        var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

        _credentialPublicKey = new CredentialPublicKey(cpk);

        unique = GetUInt16BigEndianBytes(x.Length)
            .Concat(x)
            .Concat(GetUInt16BigEndianBytes(y.Length))
            .Concat(y)
            .ToArray();

        curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[2]).Reverse().ToArray();
        kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_ECC, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, ecdsaAtt, null, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Curve mismatch between pubArea and credentialPublicKey", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoNull()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", CborNull.Instance },
            { "pubArea", pubArea },
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("CertInfo invalid parsing TPM format attStmt", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoNotByteString()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", "tomato" },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("CertInfo invalid parsing TPM format attStmt", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoByteStringZeroLen()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        if (alg is COSE.Algorithm.ES256 or COSE.Algorithm.PS256 or COSE.Algorithm.RS256)
            tpmAlg = TpmAlg.TPM_ALG_SHA256.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.ES384 or COSE.Algorithm.PS384 or COSE.Algorithm.RS384)
            tpmAlg = TpmAlg.TPM_ALG_SHA384.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.ES512 or COSE.Algorithm.PS512 or COSE.Algorithm.RS512)
            tpmAlg = TpmAlg.TPM_ALG_SHA512.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.RS1)
            tpmAlg =  TpmAlg.TPM_ALG_SHA1.ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", Array.Empty<byte>() },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("CertInfo invalid parsing TPM format attStmt", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoBadMagic()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }, // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Bad magic number 474354FF", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoBadType()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }, // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Bad structure tag 1780", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoExtraDataZeroLen()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = GetUInt16BigEndianBytes(0);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            Array.Empty<byte>(), // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea },
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Bad extraData in certInfo", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoTPM2BNameIsHandle()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, new byte[] { 0x00, 0x04 }, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Unexpected handle in TPM2B_NAME", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoTPM2BNoName()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, new byte[] { 0x00, 0x00 }, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Unexpected no name found in TPM2B_NAME", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoTPM2BExtraBytes()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length + 1);

        IEnumerable<byte> tpm2bName = new byte[] { }
            .Concat(tpm2bNameLen)
            .Concat(tpmAlg)
            .Concat(hashedPubArea)
            .Concat(new byte[] { 0x00 });

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName.ToArray(), // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Unexpected extra bytes found in TPM2B_NAME", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoTPM2BInvalidHashAlg()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, new byte[] { 0x00, 0x10 }, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("TPM_ALG_ID found in TPM2B_NAME not acceptable hash algorithm", ex.Result.Message);
    }

    [Fact]
    public void TestTPMCertInfoTPM2BInvalidTPMALGID()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, new byte[] { 0xff, 0xff }, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid TPM_ALG_ID found in TPM2B_NAME", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAlgNull()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", CborNull.Instance },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid TPM attestation algorithm", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAlgNotNumber()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", "kiwi" },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid TPM attestation algorithm", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAlgMismatch()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", COSE.Algorithm.RS1 },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Hash value mismatch extraData and attToBeSigned", ex.Result.Message);
    }

    [Fact]
    public void TestTPMPubAreaAttestedDataMismatch()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);

        hashedPubArea[^1] ^= 0xFF;

        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Hash value mismatch attested and pubArea", ex.Result.Message);
    }

    [Fact]
    public void TestTPMMissingX5c()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName.ToArray(), // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", CborNull.Instance },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Neither x5c nor ECDAA were found in the TPM attestation statement", ex.Result.Message);
    }

    [Fact]
    public void TestX5cNotArray()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", "string" },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Neither x5c nor ECDAA were found in the TPM attestation statement", ex.Result.Message);
    }

    [Fact]
    public void TestTPMX5cCountZero()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", new CborArray() },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Neither x5c nor ECDAA were found in the TPM attestation statement", ex.Result.Message);
    }

    [Fact]
    public async Task TestTPMX5cValuesNull()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", new CborArray { CborNull.Instance } },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_TpmAttestation, ex.Message);
    }

    [Fact]
    public void TestTPMX5cValuesCountZero()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", new CborArray { CborNull.Instance } },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });


        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_TpmAttestation, ex.Result.Message);
    }

    [Fact]
    public void TestTPMFirstX5cValueNotByteString()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", new CborArray { "x" } },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_TpmAttestation, ex.Result.Message);
    }

    [Fact]
    public void TestTPMFirstX5cValueByteStringZeroLen()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", new CborArray { Array.Empty<byte>() } },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_TpmAttestation, ex.Result.Message);
    }

    [Fact]
    public void TestTPMBadSignature()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);
        signature[^1] ^= 0xff;

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Bad signature in TPM with aikCert", ex.Result.Message);
    }

    [Fact]        
    public void TestTPMAikCertNotV3()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();

        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

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

        var X5c = new CborArray {
            rawAttestnCert,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea },
        });

        if (OperatingSystem.IsMacOS())
        {
            // Actually throws Interop.AppleCrypto.AppleCommonCryptoCryptographicException
            var ex = Assert.ThrowsAnyAsync<CryptographicException>(() => MakeAttestationResponseAsync());
            Assert.Equal("Unknown format in import.", ex.Result.Message);
        }

        else
        {
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.Equal("aikCert must be V3", ex.Result.Message);
        }
    }

    [Fact]
    public void TestTPMAikCertSubjectNotEmpty()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attDN = new X500DistinguishedName("CN=Testing, OU=Not Authenticator Attestation, O=FIDO2-NET-LIB, C=US");
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", X5c },
            { "sig", signature},
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("aikCert subject must be empty", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAikCertSANMissing()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        // attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);

        var tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);

        IEnumerable<byte> tpm2bName = new byte[] { }
            .Concat(tpm2bNameLen)
            .Concat(tpmAlg)
            .Concat(hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName.ToArray(), // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("SAN missing from TPM attestation certificate", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAikCertSANZeroLen()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

        var aikCertSanExt = new X509Extension("2.5.29.17", Array.Empty<byte>(), false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("SAN missing from TPM attestation certificate", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAikCertSANNoManufacturer()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

        var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x04, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x30, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x02, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
        var aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAikCertSANNoModel()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

        var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x30, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x05, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
        var aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAikCertSANNoVersion()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

        var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x30, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x06, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
        var aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature},
            { "certInfo", certInfo},
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAikCertSANInvalidManufacturer()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);

        var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x32, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x02, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
        var aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);

        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature},
            { "certInfo", certInfo},
            { "pubArea", pubArea},
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid TPM manufacturer found parsing TPM attestation", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAikCertEKUMissingTCGKP()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);

        //attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("aikCert EKU missing tcg-kp-AIKCertificate OID", ex.Result.Message);
    }

    [Fact]
    public void TestTPMAikCertCATrue()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(caExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("aikCert Basic Constraints extension CA component must be false", ex.Result.Message);
    }

    [Fact]
    public async void TestTPMAikCertMisingAAGUID()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        // attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
                    attestnCert.RawData,
                    rootCert.RawData
                };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var res = await MakeAttestationResponseAsync();

        Assert.Equal(string.Empty, res.ErrorMessage);
        Assert.Equal("ok", res.Status);
        Assert.Equal(_aaguid, res.Result.AaGuid);
        Assert.Equal(_signCount, res.Result.SignCount);
        Assert.Equal("tpm", res.Result.CredType);
        Assert.Equal(_credentialID, res.Result.Id);
        Assert.Null(res.Result.ErrorMessage);
        Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
        Assert.Null(res.Result.Status);
        Assert.Equal("Test User", res.Result.User.DisplayName);
        Assert.Equal("testuser"u8.ToArray(), res.Result.User.Id);
        Assert.Equal("testuser", res.Result.User.Name);
    }

    [Fact]
    public void TestTPMAikCertAAGUIDNotMatchAuthData()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);

        var asnEncodedAaguid = new byte[] { 0x04, 0x10, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
        var idFidoGenCeAaguidExt = new X509Extension(oidIdFidoGenCeAaguid, asnEncodedAaguid, false);

        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", X5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("aaguid malformed, expected f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0, got d0f1d0f1-d0f1-d0f1-f1d0-f1d0f1d0f1d0", ex.Result.Message);
    }

    [Fact]
    public void TestTPMECDAANotSupported()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            rootCert,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var X5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaparams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaparams);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = Concat(_authData.ToByteArray(), _clientDataHash);

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = Concat(GetUInt16BigEndianBytes(hashedData.Length), hashedData);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = Concat(tpm2bNameLen, tpmAlg, hashedPubArea);

        var certInfo = CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
            extraData, // ExtraData
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
            new byte[] { 0x00 }, // Safe
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
            tpm2bName, // TPM2BName
            new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "ecdaaKeyId", Array.Empty<byte>() },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("ECDAA support for TPM attestation is not yet implemented", ex.Result.Message);
    }

    [Fact]
    public void TestCertInfoNull()
    {
        var ex = Assert.Throws<Fido2VerificationException>(() => new CertInfo(null));
        Assert.Equal("Malformed certInfo bytes", ex.Message);
    }

    [Fact]
    public void TestCertInfoExtraBytes()
    {
        byte[] certInfo = Convert.FromHexString("ff5443478017000100002097d2ca06ce7dd7fdc56297462cd15f44ba594b0f472557a500659ccea1fcd0a6000000000000000000000000000000000000000000000000000022000b4fb39646c7a88c2322fa048ebaa748ad0c9025c6eca9e53211ffcdd2ee3ea20e000042");
        var ex = Assert.Throws<Fido2VerificationException>(() => new CertInfo(certInfo));
        Assert.Equal("Leftover bits decoding certInfo", ex.Message);
    }

    [Fact]
    public void TestPubAreaAltKeyedHash()
    {
        using var rsaAtt = RSA.Create();
        var rsaparams = rsaAtt.ExportParameters(true);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
            TpmAlg.TPM_ALG_KEYEDHASH, // Type
            tpmAlg, // Alg
            new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
            new byte[] { 0x00 }, // Policy
            new byte[] { 0x00, 0x10 }, // Symmetric
            new byte[] { 0x00, 0x10 }, // Scheme
            new byte[] { 0x80, 0x00 }, // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        var ex = Assert.Throws<Fido2VerificationException>(() => new PubArea(pubArea));
        Assert.Equal("TPM_ALG_KEYEDHASH not yet supported", ex.Message);
    }

    [Fact]
    public void TestPubAreaAltSymCipher()
    {
        using var rsaAtt = RSA.Create();
        var rsaparams = rsaAtt.ExportParameters(true);

        unique = rsaparams.Modulus;
        exponent = rsaparams.Exponent;

        var pubArea = CreatePubArea(
        TpmAlg.TPM_ALG_SYMCIPHER, // Type
        tpmAlg, // Alg
        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
        new byte[] { 0x00 }, // Policy
        new byte[] { 0x00, 0x10 }, // Symmetric
        new byte[] { 0x00, 0x10 }, // Scheme
        new byte[] { 0x80, 0x00 }, // KeyBits
        exponent, // Exponent
        curveId, // CurveID
        kdf, // KDF
        unique // Unique
        );

        var ex = Assert.Throws<Fido2VerificationException>(() => new PubArea(pubArea));
        Assert.Equal("TPM_ALG_SYMCIPHER not yet supported", ex.Message);
    }

    [Fact]
    public void TestPubAreaExtraBytes()
    {
        var pubArea = Convert.FromHexString("0001000000000000000100001000108000010001000100b181b7dac685f3df1b0a24042b6e03f55a1483499701e5d6906dc5d4bdcce496e76268ec77eeef950e4638e53c61af0230cbcaa2ea6c5d1ed640f72854765e7fbab7206242ca8ced985b4fa19be29f69abd6f73248ee0fe9c8ee427799a1b745e32211099a8a087fb636da59fb3b5e34c0d610b6342c6086c06dad0bb71439c257b99c09593ff4ab8a4046e634920f04e2297b9aa9c6ae759035af5840e497112c3949077ec7879c2108d751e9220eff6cd974db209c91489d337208775018a1a402301137f724f21ec5a239f708fd4514582bae96047c0544c7da48cb1c876cf37c1dcc6509fa22976e176a68d6f2afe67efe18e9fe8a4d891cd167eba2da0542");
        var ex = Assert.Throws<Fido2VerificationException>(() => new PubArea(pubArea));
        Assert.Equal("Leftover bytes decoding pubArea", ex.Message);
    }

    internal static byte[] CreatePubArea(
        TpmAlg type, 
        ReadOnlySpan<byte> alg, 
        ReadOnlySpan<byte> attributes, 
        ReadOnlySpan<byte> policy,
        ReadOnlySpan<byte> symmetric,
        ReadOnlySpan<byte> scheme,
        ReadOnlySpan<byte> keyBits, 
        ReadOnlySpan<byte> exponent,
        ReadOnlySpan<byte> curveID,
        ReadOnlySpan<byte> kdf, 
        ReadOnlySpan<byte> unique = default)
    {
        var raw = new MemoryStream();

        if (type is TpmAlg.TPM_ALG_ECC)
        {
            raw.Write(type.ToUInt16BigEndianBytes());
            raw.Write(alg);
            raw.Write(attributes);
            raw.Write(GetUInt16BigEndianBytes(policy.Length));
            raw.Write(policy);
            raw.Write(symmetric);
            raw.Write(scheme);
            raw.Write(curveID);
            raw.Write(kdf);
            raw.Write(unique);
        }
        else
        {
            raw.Write(type.ToUInt16BigEndianBytes());
            raw.Write(alg);
            raw.Write(attributes);
            raw.Write(GetUInt16BigEndianBytes(policy.Length));
            raw.Write(policy);
            raw.Write(symmetric);
            raw.Write(scheme);
            raw.Write(keyBits);
            raw.Write(BitConverter.GetBytes(exponent[0] + (exponent[1] << 8) + (exponent[2] << 16)));
            raw.Write(GetUInt16BigEndianBytes(unique.Length));
            raw.Write(unique);
        }

        return raw.ToArray();
    }

    internal static byte[] CreateCertInfo(
        ReadOnlySpan<byte> magic,
        ReadOnlySpan<byte> type,
        ReadOnlySpan<byte> qualifiedSigner,
        ReadOnlySpan<byte> extraData,
        ReadOnlySpan<byte> clock,
        ReadOnlySpan<byte> resetCount,
        ReadOnlySpan<byte> restartCount,
        ReadOnlySpan<byte> safe,
        ReadOnlySpan<byte> firmwareRevision,
        ReadOnlySpan<byte> tPM2BName, 
        ReadOnlySpan<byte> attestedQualifiedNameBuffer)
    {
        var stream = new MemoryStream();

        stream.Write(magic);
        stream.Write(type);
        stream.Write(qualifiedSigner);
        stream.Write(extraData);
        stream.Write(clock);
        stream.Write(resetCount);
        stream.Write(restartCount);
        stream.Write(safe);
        stream.Write(firmwareRevision);
        stream.Write(tPM2BName);
        stream.Write(attestedQualifiedNameBuffer);

        return stream.ToArray();
    }

    internal static byte[] GetUInt16BigEndianBytes(int value)
    {
        return GetUInt16BigEndianBytes((UInt16)value);
    }

    internal static byte[] GetUInt16BigEndianBytes(UInt16 value)
    {
        var buffer = new byte[2];

        BinaryPrimitives.WriteUInt16BigEndian(buffer, value);

        return buffer;
    }


    internal static CredentialPublicKey GetRSACredentialPublicKey(COSE.KeyType type, COSE.Algorithm alg, RSAParameters rsaparams)
    {
        var cpk = new CborMap {
            { COSE.KeyCommonParameter.KeyType, type },
            { COSE.KeyCommonParameter.Alg, alg },
            { COSE.KeyTypeParameter.N, rsaparams.Modulus },
            { COSE.KeyTypeParameter.E, rsaparams.Exponent }
        };

        return new CredentialPublicKey(cpk);
    }

    internal static RSASignaturePadding GetRSASignaturePaddingForCoseAlgorithm(COSE.Algorithm alg)
    {
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms

        if (alg is COSE.Algorithm.RS1 or COSE.Algorithm.RS256 or COSE.Algorithm.RS384 or COSE.Algorithm.RS512)
        {
            return RSASignaturePadding.Pkcs1;
        }
        else
        {
            return RSASignaturePadding.Pss;
        }
    }

    internal static TpmAlg GetTmpAlg(COSE.Algorithm alg)
    {
        if (alg is COSE.Algorithm.ES256 or COSE.Algorithm.PS256 or COSE.Algorithm.RS256)
        {
            return TpmAlg.TPM_ALG_SHA256;
        }
        else if (alg is COSE.Algorithm.ES384 or COSE.Algorithm.PS384 or COSE.Algorithm.RS384)
        {
            return TpmAlg.TPM_ALG_SHA384;
        }
        else if (alg is COSE.Algorithm.ES512 or COSE.Algorithm.PS512 or COSE.Algorithm.RS512)
        {
            return TpmAlg.TPM_ALG_SHA512;
        }
        else if (alg is COSE.Algorithm.RS1)
        {
            return TpmAlg.TPM_ALG_SHA1;
        }
        else
        {
            throw new Exception($"Unknown alg. Was {alg}");
        }
    }
}
