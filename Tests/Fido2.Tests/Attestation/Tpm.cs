using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using fido2_net_lib;
using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Moq;

namespace Test.Attestation;

public class Tpm : Fido2Tests.Attestation
{
    private readonly X500DistinguishedName attDN = new("");
    private X509Certificate2 attestnCert;
    private readonly DateTimeOffset notBefore, notAfter;
    private readonly X509EnhancedKeyUsageExtension tcgKpAIKCertExt;
    private readonly X509Extension aikCertSanExt;
    private byte[] unique, exponent, curveId, kdf;
    private byte[] tpmAlg;

    private static readonly Dictionary<TpmAlg, ushort> TpmAlgToDigestSizeMap = new()
    {
        { TpmAlg.TPM_ALG_SHA1,   (160/8) },
        { TpmAlg.TPM_ALG_SHA256, (256/8) },
        { TpmAlg.TPM_ALG_SHA384, (384/8) },
        { TpmAlg.TPM_ALG_SHA512, (512/8) }
    };

    private static readonly Dictionary<int, TpmEccCurve> CoseCurveToTpm = new()
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
            manufacturer: "id:4D534654", // 'MSFT' Microsoft
            model: "FIDO2-NET-LIB-TEST-TPM",
            version: "id:F1D00002"
        );

        aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);
    }

    [Fact]
    public async Task TestTPM()
    {
        foreach (var (type, alg, curve) in Fido2Tests._validCOSEParameters)
        {
            if (type is COSE.KeyType.OKP)
            {
                continue; // no OKP support in TPM
            }

            if (type is COSE.KeyType.EC2 && alg is COSE.Algorithm.ES256K)
            {
                continue; // no secp256k1 support in TPM
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
                        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
                        attRequest.CertificateExtensions.Add(aikCertSanExt);
                        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                        byte[] serial = RandomNumberGenerator.GetBytes(12);

                        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
                        {
                            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                        }

                        var x5c = new CborArray {
                            attestnCert.RawData,
                            rootCert.RawData
                        };

                        var ecParams = ecdsaAtt.ExportParameters(true);

                        var cpk = new CborMap {
                            { COSE.KeyCommonParameter.KeyType, type },
                            { COSE.KeyCommonParameter.Alg, alg},
                            { COSE.KeyTypeParameter.X, ecParams.Q.X},
                            { COSE.KeyTypeParameter.Y, ecParams.Q.Y},
                            { COSE.KeyTypeParameter.Crv, curve},
                        };

                        var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                        var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                        _credentialPublicKey = new CredentialPublicKey(cpk);

                        unique = [
                            .. GetUInt16BigEndianBytes(x.Length),
                            .. x,
                            .. GetUInt16BigEndianBytes(y.Length),
                            .. y
                        ];

                        curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[(int)cpk[COSE.KeyTypeParameter.Crv]]).Reverse().ToArray();
                        kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL); // should this be big endian?

                        var pubArea = PubAreaHelper.CreatePubArea(
                            TpmAlg.TPM_ALG_ECC, // Type
                            tpmAlg, // Alg
                            [0x00, 0x00, 0x00, 0x00], // Attributes
                            [0x00], // Policy
                            [0x00, 0x10], // Symmetric
                            [0x00, 0x10], // Scheme
                            [0x80, 0x00], // KeyBits
                            exponent, // Exponent
                            curveId, // CurveID
                            kdf, // KDF
                            unique // Unique
                        );

                        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
                        byte[] hashedData = _attToBeSignedHash(hashAlg);
                        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

                        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];

                        var tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);

                        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

                        var certInfo = CertInfoHelper.CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            [0x00, 0x01, 0x00], // QualifiedSigner
                            extraData, // ExtraData
                            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
                            [0x00, 0x00, 0x00, 0x00], // ResetCount
                            [0x00, 0x00, 0x00, 0x00], // RestartCount
                            [0x00], // Safe
                            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
                            tpm2bName, // TPM2BName
                            [0x00, 0x00] // AttestedQualifiedNameBuffer
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
                        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
                        attRequest.CertificateExtensions.Add(aikCertSanExt);
                        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

                        byte[] serial = RandomNumberGenerator.GetBytes(12);

                        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
                        {
                            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                        }

                        var x5c = new CborArray {
                            attestnCert.RawData,
                            rootCert.RawData
                        };

                        var rsaParams = rsaAtt.ExportParameters(true);

                        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

                        unique = rsaParams.Modulus;
                        exponent = rsaParams.Exponent;

                        var pubArea = PubAreaHelper.CreatePubArea(
                            TpmAlg.TPM_ALG_RSA, // Type
                            tpmAlg, // Alg
                            [0x00, 0x00, 0x00, 0x00], // Attributes
                            [0x00], // Policy
                            [0x00, 0x10], // Symmetric
                            [0x00, 0x10], // Scheme
                            [0x80, 0x00], // KeyBits
                            exponent, // Exponent
                            curveId, // CurveID
                            kdf, // KDF
                            unique // Unique
                        );

                        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

                        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);

                        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
                        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

                        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
                        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
                        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

                        var certInfo = CertInfoHelper.CreateCertInfo(
                            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                            [0x00, 0x01, 0x00], // QualifiedSigner
                            extraData, // ExtraData
                            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
                            [0x00, 0x00, 0x00, 0x00], // ResetCount
                            [0x00, 0x00, 0x00, 0x00], // RestartCount
                            [0x00], // Safe
                            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
                            tpm2bName, // TPM2BName
                            [0x00, 0x00] // AttestedQualifiedNameBuffer
                        );

                        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

                        _attestationObject.Set("attStmt", new CborMap {
                            { "ver", "2.0" },
                            { "alg", alg },
                            { "x5c", x5c },
                            { "sig", signature },
                            { "certInfo", certInfo },
                            { "pubArea", pubArea }
                        });
                    }

                    break;
            }
            var credential = await MakeAttestationResponseAsync();

            Assert.Equal(_aaguid, credential.AaGuid);
            Assert.Equal(_signCount, credential.SignCount);
            Assert.Equal("tpm", credential.AttestationFormat);
            Assert.Equal("attca", credential.AttestationType);
            Assert.Equal(_credentialID, credential.Id);
            Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
            Assert.Equal("Test User", credential.User.DisplayName);
            Assert.Equal("testuser"u8.ToArray(), credential.User.Id);
            Assert.Equal("testuser", credential.User.Name);
            _attestationObject = new CborMap { { "fmt", "tpm" } };
            Assert.Equal([AuthenticatorTransport.Internal], credential.Transports);
        }
    }

    /// <summary>
    /// TPMU_ASYM_SCHEME (via TPMT_ECC_SCHEME) is a union: unless the scheme selector is TPM_ALG_NULL, it is
    /// followed by scheme-specific detail -- for TPM_ALG_ECDSA, a TPMI_ALG_HASH naming the signature hash
    /// algorithm. PubArea previously assumed the selector was the entire field, so a pubArea naming an explicit
    /// hash algorithm (as opposed to TPM_ALG_NULL, which fido2-net-lib's own test fixtures always use) misaligned
    /// every field read after it and eventually crashed with a NullReferenceException reading the EC point.
    /// </summary>
    [Fact]
    public async Task TestTPMEccSchemeWithHashAlgorithmDetailIsParsedCorrectly()
    {
        var type = COSE.KeyType.EC2;
        var alg = COSE.Algorithm.ES256;
        tpmAlg = GetTmpAlg(alg).ToUInt16BigEndianBytes();

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray { attestnCert.RawData, rootCert.RawData };

        var ecParams = ecdsaAtt.ExportParameters(true);

        var cpk = new CborMap {
            { COSE.KeyCommonParameter.KeyType, type },
            { COSE.KeyCommonParameter.Alg, alg},
            { COSE.KeyTypeParameter.X, ecParams.Q.X},
            { COSE.KeyTypeParameter.Y, ecParams.Q.Y},
            { COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P256},
        };

        var x = (byte[])cpk[COSE.KeyTypeParameter.X];
        var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

        _credentialPublicKey = new CredentialPublicKey(cpk);

        unique = [
            .. GetUInt16BigEndianBytes(x.Length),
            .. x,
            .. GetUInt16BigEndianBytes(y.Length),
            .. y
        ];

        curveId = BitConverter.GetBytes((ushort)TpmEccCurve.TPM_ECC_NIST_P256).Reverse().ToArray();
        kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_ECC, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, (byte)TpmAlg.TPM_ALG_ECDSA, 0x00, (byte)TpmAlg.TPM_ALG_SHA256], // Scheme: ECDSA with an explicit SHA-256 hashAlg detail
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = _attToBeSignedHash(hashAlg);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];

        var tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);

        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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

        var credential = await MakeAttestationResponseAsync();

        Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
    }

    [Fact]
    public async Task TestTPMAikCertSANTCGConformant()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] asnEncodedSAN = TpmSanEncoder.Encode(
            manufacturer: "id:4D534654", // 'MSFT' Microsoft
            model: "FIDO2-NET-LIB-TestTPMAikCertSANTCGConformant",
            version: "id:F1D00002"
        );

        var aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);

        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm1bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm1bName = [.. tpm1bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm1bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var credential = await MakeAttestationResponseAsync();

        Assert.Equal(_aaguid, credential.AaGuid);
        Assert.Equal(_signCount, credential.SignCount);
        Assert.Equal("tpm", credential.AttestationFormat);
        Assert.Equal(_credentialID, credential.Id);
        Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
        Assert.Equal("Test User", credential.User.DisplayName);
        Assert.Equal("testuser"u8, credential.User.Id);
        Assert.Equal("testuser", credential.User.Name);
        Assert.Equal([AuthenticatorTransport.Internal], credential.Transports);
    }

    [Fact]
    public async Task TestTPMSigNull()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", CborNull.Instance },
            { "certInfo", certInfo },
            { "pubArea", pubArea },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid TPM attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestTPMSigNotByteString()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];
        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);

        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", x5c },
            { "sig", "strawberries" },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid TPM attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestTPMSigByteStringZeroLen()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", x5c },
            { "sig", Array.Empty<byte>() },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid TPM attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestTPMVersionNot2()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        if (alg is COSE.Algorithm.ES256 or COSE.Algorithm.PS256 or COSE.Algorithm.RS256)
            tpmAlg = TpmAlg.TPM_ALG_SHA256.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.ES384 or COSE.Algorithm.PS384 or COSE.Algorithm.RS384)
            tpmAlg = TpmAlg.TPM_ALG_SHA384.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.ES512 or COSE.Algorithm.PS512 or COSE.Algorithm.RS512)
            tpmAlg = TpmAlg.TPM_ALG_SHA512.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.RS1)
            tpmAlg = TpmAlg.TPM_ALG_SHA1.ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "3.0" },
            { "alg", (int)alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal("FIDO2 only supports TPM 2.0", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaNull()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);

        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo},
            { "pubArea", CborNull.Instance },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Missing or malformed pubArea", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaNotByteString()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", "banana" }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Missing or malformed pubArea", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaByteStringZeroLen()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", Array.Empty<byte>() }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Missing or malformed pubArea", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaUniqueNull()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;
        byte[] policy = [0x00];

        #pragma warning disable format
        byte[] pubArea = [
            .. TpmAlg.TPM_ALG_RSA.ToUInt16BigEndianBytes(),
            .. tpmAlg,
            0x00, 0x00, 0x00, 0x00,
            .. GetUInt16BigEndianBytes(policy.Length),
            .. policy,
            0x00, 0x10,
            0x00, 0x10,
            0x80, 0x00,
            .. PubAreaHelper.GetUInt32BigEndianBytes(exponent)
        ];
        #pragma warning restore format

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Missing or malformed pubArea", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaUniqueByteStringZeroLen()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            [] // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];

        var tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);

        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Missing or malformed pubArea", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaUniquePublicKeyMismatch()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique.Reverse().ToArray() // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Public key mismatch between pubArea and credentialPublicKey", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaUniqueExponentMismatch()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            [0x00, 0x01, 0x00], // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Public key exponent mismatch between pubArea and credentialPublicKey", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaUniqueXValueMismatch()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var ecParams = ecdsaAtt.ExportParameters(true);

        var cpk = new CborMap {
            { COSE.KeyCommonParameter.KeyType, type },
            { COSE.KeyCommonParameter.Alg, alg },
            { COSE.KeyTypeParameter.X, ecParams.Q.X },
            { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
            { COSE.KeyTypeParameter.Crv, curve }
        };

        var x = ((byte[])cpk[COSE.KeyTypeParameter.X]).Reverse().ToArray();
        var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

        _credentialPublicKey = new CredentialPublicKey(cpk);

        unique = [
            .. GetUInt16BigEndianBytes(x.Length),
            .. x,
            .. GetUInt16BigEndianBytes(y.Length),
            .. y
        ];

        curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[(int)cpk[COSE.KeyTypeParameter.Crv]]).Reverse().ToArray();
        kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_ECC, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);
        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, ecdsaAtt, null, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", x5c },
            { "sig", signature},
            { "certInfo", certInfo},
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("X-coordinate mismatch between pubArea and credentialPublicKey", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaUniqueYValueMismatch()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var ecParams = ecdsaAtt.ExportParameters(true);

        var cpk = new CborMap {
            { COSE.KeyCommonParameter.KeyType, type },
            { COSE.KeyCommonParameter.Alg, alg },
            { COSE.KeyTypeParameter.X, ecParams.Q.X },
            { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
            { COSE.KeyTypeParameter.Crv, curve }
        };

        var x = (byte[])cpk[COSE.KeyTypeParameter.X];
        var y = ((byte[])cpk[COSE.KeyTypeParameter.Y]).Reverse().ToArray();

        _credentialPublicKey = new CredentialPublicKey(cpk);

        unique = [
            .. GetUInt16BigEndianBytes(x.Length),
            .. x,
            .. GetUInt16BigEndianBytes(y.Length),
            .. y
        ];

        curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[(int)cpk[COSE.KeyTypeParameter.Crv]]).Reverse().ToArray();
        kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_ECC, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Y-coordinate mismatch between pubArea and credentialPublicKey", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaUniqueCurveMismatch()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var ecParams = ecdsaAtt.ExportParameters(true);

        var cpk = new CborMap {
            { COSE.KeyCommonParameter.KeyType, type },
            { COSE.KeyCommonParameter.Alg, alg },
            { COSE.KeyTypeParameter.X, ecParams.Q.X },
            { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
            { COSE.KeyTypeParameter.Crv, curve }
        };

        var x = (byte[])cpk[COSE.KeyTypeParameter.X];
        var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

        _credentialPublicKey = new CredentialPublicKey(cpk);

        unique = [
            .. GetUInt16BigEndianBytes(x.Length),
            .. x,
            .. GetUInt16BigEndianBytes(y.Length),
            .. y
        ];

        curveId = BitConverter.GetBytes((ushort)CoseCurveToTpm[2]).Reverse().ToArray();
        kdf = BitConverter.GetBytes((ushort)TpmAlg.TPM_ALG_NULL);

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_ECC, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Curve mismatch between pubArea and credentialPublicKey", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoNull()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", CborNull.Instance },
            { "pubArea", pubArea },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("CertInfo invalid parsing TPM format attStmt", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoNotByteString()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", "tomato" },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("CertInfo invalid parsing TPM format attStmt", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoByteStringZeroLen()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];

        if (alg is COSE.Algorithm.ES256 or COSE.Algorithm.PS256 or COSE.Algorithm.RS256)
            tpmAlg = TpmAlg.TPM_ALG_SHA256.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.ES384 or COSE.Algorithm.PS384 or COSE.Algorithm.RS384)
            tpmAlg = TpmAlg.TPM_ALG_SHA384.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.ES512 or COSE.Algorithm.PS512 or COSE.Algorithm.RS512)
            tpmAlg = TpmAlg.TPM_ALG_SHA512.ToUInt16BigEndianBytes();
        if (alg is COSE.Algorithm.RS1)
            tpmAlg = TpmAlg.TPM_ALG_SHA1.ToUInt16BigEndianBytes();

        using RSA rsaRoot = RSA.Create();
        RSASignaturePadding padding = GetRSASignaturePaddingForCoseAlgorithm(alg);

        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
        rootRequest.CertificateExtensions.Add(caExt);

        using var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var rsaAtt = RSA.Create();
        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", Array.Empty<byte>() },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("CertInfo invalid parsing TPM format attStmt", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoBadMagic()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            [0x47, 0x43, 0x54, 0xff], // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Bad magic number 474354FF", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoBadType()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            [0x17, 0x80], // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Bad structure tag 1780", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoExtraDataZeroLen()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = GetUInt16BigEndianBytes(0);
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            [], // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Bad extraData in certInfo", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoTPM2BNameIsHandle()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, 0x00, 0x04, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Unexpected handle in TPM2B_NAME", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoTPM2BNoName()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, 0x00, 0x00, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Unexpected no name found in TPM2B_NAME", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoTPM2BExtraBytes()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length + 1);

        byte[] tpm2bName = [
            .. tpm2bNameLen,
            .. tpmAlg,
            .. hashedPubArea,
            0x00
        ];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Unexpected extra bytes found in TPM2B_NAME", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoTPM2BInvalidHashAlg()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, 0x00, 0x10, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSignerdo
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("TPM_ALG_ID found in TPM2B_NAME not acceptable hash algorithm", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoTPM2BInvalidTPMALGID()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, 0xff, 0xff, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid TPM_ALG_ID found in TPM2B_NAME", ex.Message);
    }

    [Fact]
    public async Task TestTPMAlgNull()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", CborNull.Instance },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid TPM attestation algorithm", ex.Message);
    }

    [Fact]
    public async Task TestTPMAlgNotNumber()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", "kiwi" },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid TPM attestation algorithm", ex.Message);
    }

    [Fact]
    public async Task TestTPMAlgMismatch()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", COSE.Algorithm.RS1 },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Hash value mismatch extraData and attToBeSigned", ex.Message);
    }

    [Fact]
    public async Task TestTPMPubAreaAttestedDataMismatch()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);

        hashedPubArea[^1] ^= 0xFF;

        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Hash value mismatch attested and pubArea", ex.Message);
    }

    [Fact]
    public async Task TestTPMMissingX5c()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Neither x5c nor ECDAA were found in the TPM attestation statement", ex.Message);
    }

    [Fact]
    public async Task TestX5cNotArray()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Neither x5c nor ECDAA were found in the TPM attestation statement", ex.Message);
    }

    [Fact]
    public async Task TestTPMX5cCountZero()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Neither x5c nor ECDAA were found in the TPM attestation statement", ex.Message);
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_TpmAttestation, ex.Message);
    }

    [Fact]
    public async Task TestTPMX5cValuesCountZero()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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


        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_TpmAttestation, ex.Message);
    }

    [Fact]
    public async Task TestTPMFirstX5cValueNotByteString()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_TpmAttestation, ex.Message);
    }

    [Fact]
    public async Task TestTPMFirstX5cValueByteStringZeroLen()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_TpmAttestation, ex.Message);
    }

    [Fact]
    public async Task TestTPMBadSignature()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);
        signature[^1] ^= 0xff;

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Bad signature in TPM with aikCert", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertNotV3()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var rawAttestnCert = attestnCert.RawData;
        rawAttestnCert[12] = 0x41;

        var x5c = new CborArray {
            rawAttestnCert,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea },
        });

        if (OperatingSystem.IsMacOS())
        {
            // Actually throws Interop.AppleCrypto.AppleCommonCryptoCryptographicException
            var ex = await Assert.ThrowsAnyAsync<CryptographicException>(MakeAttestationResponseAsync);
            Assert.Equal("Unknown format in import.", ex.Message);
        }

        else
        {
            var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
            Assert.Equal("aikCert must be V3", ex.Message);
        }
    }

    [Fact]
    public async Task TestTPMAikCertSubjectNotEmpty()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", x5c },
            { "sig", signature},
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("aikCert subject must be empty", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertSANMissing()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        // attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];

        var tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);

        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName.ToArray(), // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("SAN missing from TPM attestation certificate", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertSANZeroLen()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        var aikCertSanExt = new X509Extension("2.5.29.17", Array.Empty<byte>(), false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("SAN missing from TPM attestation certificate", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertSANNoManufacturer()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x04, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x30, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x02, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
        var aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertSANNoModel()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x30, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x05, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
        var aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertSANNoVersion()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x30, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x06, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
        var aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature},
            { "certInfo", certInfo},
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertSANInvalidManufacturer()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        var asnEncodedSAN = new byte[] { 0x30, 0x53, 0xA4, 0x51, 0x30, 0x4F, 0x31, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x46, 0x46, 0x46, 0x46, 0x31, 0x44, 0x32, 0x30, 0x1F, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x02, 0x0C, 0x16, 0x46, 0x49, 0x44, 0x4F, 0x32, 0x2D, 0x4E, 0x45, 0x54, 0x2D, 0x4C, 0x49, 0x42, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x54, 0x50, 0x4D, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x03, 0x0C, 0x0B, 0x69, 0x64, 0x3A, 0x46, 0x31, 0x44, 0x30, 0x30, 0x30, 0x30, 0x32 };
        var aikCertSanExt = new X509Extension("2.5.29.17", asnEncodedSAN, false);

        attRequest.CertificateExtensions.Add(aikCertSanExt);

        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature},
            { "certInfo", certInfo},
            { "pubArea", pubArea},
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid TPM manufacturer found parsing TPM attestation", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertEKUMissingTCGKP()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);

        //attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("aikCert EKU missing tcg-kp-AIKCertificate OID", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertCATrue()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("aikCert Basic Constraints extension CA component must be false", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertMisingAAGUID()
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

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var crendential = await MakeAttestationResponseAsync();

        Assert.Equal(_aaguid, crendential.AaGuid);
        Assert.Equal(_signCount, crendential.SignCount);
        Assert.Equal("tpm", crendential.AttestationFormat);
        Assert.Equal(_credentialID, crendential.Id);
        Assert.Equal(_credentialPublicKey.GetBytes(), crendential.PublicKey);
        Assert.Equal("Test User", crendential.User.DisplayName);
        Assert.Equal("testuser"u8.ToArray(), crendential.User.Id);
        Assert.Equal("testuser", crendential.User.Name);
        Assert.Equal([AuthenticatorTransport.Internal], crendential.Transports);
    }

    [Fact]
    public async Task TestTPMAikCertAAGUIDNotMatchAuthData()
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
        var idFidoGenCeAaguidExt = new X509Extension(oidIdFidoGenCeAaGuid, asnEncodedAaguid, false);

        attRequest.CertificateExtensions.Add(idFidoGenCeAaguidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(type, alg, certInfo, null, rsaAtt, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", (int)alg },
            { "x5c", x5c },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("aaguid malformed, expected f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0, got d0f1d0f1-d0f1-d0f1-f1d0-f1d0f1d0f1d0", ex.Message);
    }

    [Fact]
    public async Task TestTPMECDAANotSupported()
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
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(rootCert, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            rootCert.RawData
        };

        var rsaParams = rsaAtt.ExportParameters(true);

        _credentialPublicKey = GetRSACredentialPublicKey(type, alg, rsaParams);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_RSA, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            exponent, // Exponent
            curveId, // CurveID
            kdf, // KDF
            unique // Unique
        );

        byte[] data = [.. _authData.ToByteArray(), .. _clientDataHash];

        var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(alg);
        byte[] hashedData = CryptoUtils.HashData(hashAlg, data);
        byte[] hashedPubArea = CryptoUtils.HashData(hashAlg, pubArea);

        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bNameLen = GetUInt16BigEndianBytes(tpmAlg.Length + hashedPubArea.Length);
        byte[] tpm2bName = [.. tpm2bNameLen, .. tpmAlg, .. hashedPubArea];

        var certInfo = CertInfoHelper.CreateCertInfo(
            new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
            new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
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

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("ECDAA support for TPM attestation is not yet implemented", ex.Message);
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
        var rsaParams = rsaAtt.ExportParameters(true);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_KEYEDHASH, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
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
        var rsaParams = rsaAtt.ExportParameters(true);

        unique = rsaParams.Modulus;
        exponent = rsaParams.Exponent;

        var pubArea = PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_SYMCIPHER, // Type
            tpmAlg, // Alg
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
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

    // The tests below share one builder: a fresh ES256 AIK (chained to a root) certifies whatever pubArea the test
    // hands it over the current _authData and _clientDataHash, so each test only spells out what it is varying.

    private (X509Certificate2 aikCert, X509Certificate2 rootCert, ECDsa aikKey) CreateEcdsaAikPki(X509Extension sanExt = null)
    {
        var ecdsaRoot = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);
        var rootCert = rootRequest.CreateSelfSigned(notBefore, notAfter);

        var aikKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attRequest = new CertificateRequest(attDN, aikKey, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);
        attRequest.CertificateExtensions.Add(sanExt ?? aikCertSanExt);
        attRequest.CertificateExtensions.Add(tcgKpAIKCertExt);
        var aikCert = attRequest.Create(rootCert, notBefore, notAfter, RandomNumberGenerator.GetBytes(12));

        return (aikCert, rootCert, aikKey);
    }

    private static byte[] CreateEccPubArea(ECParameters ecParams, TpmEccCurve curve)
    {
        return PubAreaHelper.CreatePubArea(
            TpmAlg.TPM_ALG_ECC,
            TpmAlg.TPM_ALG_SHA256.ToUInt16BigEndianBytes(),
            [0x00, 0x00, 0x00, 0x00], // Attributes
            [0x00], // Policy
            [0x00, 0x10], // Symmetric
            [0x00, 0x10], // Scheme
            [0x80, 0x00], // KeyBits
            [0x01, 0x00, 0x01], // Exponent (unused for ECC)
            GetUInt16BigEndianBytes((ushort)curve), // CurveID
            TpmAlg.TPM_ALG_NULL.ToUInt16BigEndianBytes(), // KDF
            [.. GetUInt16BigEndianBytes(ecParams.Q.X.Length), .. ecParams.Q.X, .. GetUInt16BigEndianBytes(ecParams.Q.Y.Length), .. ecParams.Q.Y]
        );
    }

    /// <summary>
    /// An RSA pubArea with the exponent field spelled out exactly, so a test can pin down how the 4 octets are read.
    /// </summary>
    private static byte[] CreateRsaPubArea(byte[] modulus, byte[] exponentField)
    {
        Assert.Equal(4, exponentField.Length);

        return
        [
            .. TpmAlg.TPM_ALG_RSA.ToUInt16BigEndianBytes(),
            .. TpmAlg.TPM_ALG_SHA256.ToUInt16BigEndianBytes(),
            0x00, 0x00, 0x00, 0x00, // Attributes
            0x00, 0x01, 0x00, // Policy
            0x00, 0x10, // Symmetric
            0x00, 0x10, // Scheme
            0x08, 0x00, // KeyBits
            .. exponentField,
            .. GetUInt16BigEndianBytes(modulus.Length),
            .. modulus
        ];
    }

    /// <summary>
    /// Adds a "tpm" attStmt to <see cref="Fido2Tests.Attestation._attestationObject"/> in which a fresh ES256 AIK
    /// certifies <paramref name="pubArea"/> over the current authenticator data and client data hash.
    /// <see cref="Fido2Tests.Attestation._credentialPublicKey"/> must already be set.
    /// </summary>
    private void AddTpmAttStmt(byte[] pubArea, byte[] certInfo = null, X509Extension sanExt = null)
    {
        var (aikCert, rootCert, aikKey) = CreateEcdsaAikPki(sanExt);
        var nameAlg = TpmAlg.TPM_ALG_SHA256.ToUInt16BigEndianBytes();

        byte[] hashedData = _attToBeSignedHash(HashAlgorithmName.SHA256);
        byte[] hashedPubArea = SHA256.HashData(pubArea);
        byte[] extraData = [.. GetUInt16BigEndianBytes(hashedData.Length), .. hashedData];
        byte[] tpm2bName = [.. GetUInt16BigEndianBytes(nameAlg.Length + hashedPubArea.Length), .. nameAlg, .. hashedPubArea];

        certInfo ??= CertInfoHelper.CreateCertInfo(
            [0xff, 0x54, 0x43, 0x47], // Magic
            [0x80, 0x17], // Type
            [0x00, 0x01, 0x00], // QualifiedSigner
            extraData, // ExtraData
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Clock
            [0x00, 0x00, 0x00, 0x00], // ResetCount
            [0x00, 0x00, 0x00, 0x00], // RestartCount
            [0x00], // Safe
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // FirmwareVersion
            tpm2bName, // TPM2BName
            [0x00, 0x00] // AttestedQualifiedNameBuffer
        );

        byte[] signature = Fido2Tests.SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, certInfo, aikKey, null, null);

        _attestationObject.Add("attStmt", new CborMap {
            { "ver", "2.0" },
            { "alg", COSE.Algorithm.ES256 },
            { "x5c", new CborArray { aikCert.RawData, rootCert.RawData } },
            { "sig", signature },
            { "certInfo", certInfo },
            { "pubArea", pubArea }
        });
    }

    [Fact]
    public async Task TestTPMOkpCredentialPublicKeyRejected()
    {
        // pubArea describes a genuine (but unrelated) P-256 key; the credential public key is an Ed25519 key that
        // no TPM 2.0 can hold, so the certInfo cannot be certifying it, whatever the AIK signed.
        Fido2Tests.MakeEdDSA(out _, out var publicKey, out _);
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519, publicKey);

        using var tpmKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        AddTpmAttStmt(CreateEccPubArea(tpmKey.ExportParameters(false), TpmEccCurve.TPM_ECC_NIST_P256));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("TPM attestation requires an RSA or EC2 credential public key, got OKP", ex.Message);
    }

    [Fact]
    public async Task TestTPMRsaPubAreaExplicitBigEndianExponentAccepted()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        Assert.Equal([0x01, 0x00, 0x01], rsaParams.Exponent);
        _credentialPublicKey = GetRSACredentialPublicKey(COSE.KeyType.RSA, COSE.Algorithm.RS256, rsaParams);

        // 65537 as TPM marshals it: a 32-bit big-endian field
        AddTpmAttStmt(CreateRsaPubArea(rsaParams.Modulus, [0x00, 0x01, 0x00, 0x01]));

        var credential = await MakeAttestationResponseAsync();
        Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
    }

    [Fact]
    public async Task TestTPMRsaPubAreaDefaultExponentAccepted()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        _credentialPublicKey = GetRSACredentialPublicKey(COSE.KeyType.RSA, COSE.Algorithm.RS256, rsaParams);

        // zero means "the default of 2^16 + 1", which is what Windows-issued attestations carry
        AddTpmAttStmt(CreateRsaPubArea(rsaParams.Modulus, [0x00, 0x00, 0x00, 0x00]));

        var credential = await MakeAttestationResponseAsync();
        Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
    }

    [Fact]
    public async Task TestTPMRsaPubAreaLittleEndianExponentRejected()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        _credentialPublicKey = GetRSACredentialPublicKey(COSE.KeyType.RSA, COSE.Algorithm.RS256, rsaParams);

        // 65537 written little-endian is 0x01000100 in canonical form: a different exponent
        AddTpmAttStmt(CreateRsaPubArea(rsaParams.Modulus, [0x01, 0x00, 0x01, 0x00]));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Public key exponent mismatch between pubArea and credentialPublicKey", ex.Message);
    }

    [Fact]
    public async Task TestTPMRsaCoseExponentOfAnyLengthAccepted()
    {
        using var rsa = RSA.Create(2048);
        var modulus = rsa.ExportParameters(false).Modulus;

        // COSE gives e as an unsigned big-endian integer of whatever length it needs (RFC 8230 section 4)
        foreach (var (coseExponent, pubAreaExponent) in new (byte[], byte[])[]
        {
            ([0x03], [0x00, 0x00, 0x00, 0x03]),
            ([0x00, 0x01, 0x00, 0x01], [0x00, 0x01, 0x00, 0x01]),
            ([0x00, 0x00, 0x01, 0x00, 0x01], [0x00, 0x01, 0x00, 0x01]),
        })
        {
            _attestationObject = new CborMap { { "fmt", "tpm" } };
            _credentialPublicKey = new CredentialPublicKey(new CborMap {
                { COSE.KeyCommonParameter.KeyType, COSE.KeyType.RSA },
                { COSE.KeyCommonParameter.Alg, COSE.Algorithm.RS256 },
                { COSE.KeyTypeParameter.N, modulus },
                { COSE.KeyTypeParameter.E, coseExponent }
            });

            AddTpmAttStmt(CreateRsaPubArea(modulus, pubAreaExponent));

            var credential = await MakeAttestationResponseAsync();
            Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
        }
    }

    [Fact]
    public async Task TestTPMRsaCoseExponentWiderThan32BitsRejected()
    {
        using var rsa = RSA.Create(2048);
        var modulus = rsa.ExportParameters(false).Modulus;

        _credentialPublicKey = new CredentialPublicKey(new CborMap {
            { COSE.KeyCommonParameter.KeyType, COSE.KeyType.RSA },
            { COSE.KeyCommonParameter.Alg, COSE.Algorithm.RS256 },
            { COSE.KeyTypeParameter.N, modulus },
            { COSE.KeyTypeParameter.E, new byte[] { 0x01, 0x00, 0x01, 0x00, 0x01 } }
        });

        AddTpmAttStmt(CreateRsaPubArea(modulus, [0x00, 0x01, 0x00, 0x01]));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Public key exponent mismatch between pubArea and credentialPublicKey", ex.Message);
    }

    [Fact]
    public async Task TestTPMRsaCredentialPublicKeyWithEccPubAreaRejected()
    {
        using var rsa = RSA.Create(2048);
        _credentialPublicKey = GetRSACredentialPublicKey(COSE.KeyType.RSA, COSE.Algorithm.RS256, rsa.ExportParameters(false));

        using var tpmKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        AddTpmAttStmt(CreateEccPubArea(tpmKey.ExportParameters(false), TpmEccCurve.TPM_ECC_NIST_P256));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("pubArea type TPM_ALG_ECC does not match RSA credentialPublicKey", ex.Message);
    }

    [Fact]
    public async Task TestTPMEccCredentialPublicKeyWithRsaPubAreaRejected()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecParams.Q.X, ecParams.Q.Y);

        using var rsa = RSA.Create(2048);
        AddTpmAttStmt(CreateRsaPubArea(rsa.ExportParameters(false).Modulus, [0x00, 0x01, 0x00, 0x01]));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("pubArea type TPM_ALG_RSA does not match EC2 credentialPublicKey", ex.Message);
    }

    [Fact]
    public async Task TestTPMCredentialPublicKeyCurveWithoutTpmEquivalentRejected()
    {
        if (OperatingSystem.IsMacOS())
            return; // secP256k1 is not supported on macOS

        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey((COSE.KeyType.EC2, COSE.Algorithm.ES256K, COSE.EllipticCurve.P256K));

        using var tpmKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        AddTpmAttStmt(CreateEccPubArea(tpmKey.ExportParameters(false), TpmEccCurve.TPM_ECC_NIST_P256));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Curve P256K of credentialPublicKey is not supported by TPM attestation", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertSANManufacturerAddedInRegistryVersion106()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecParams.Q.X, ecParams.Q.Y);

        // 'HISI' Huawei, added to the TCG TPM Vendor ID Registry in version 1.05
        var sanExt = new X509Extension("2.5.29.17", TpmSanEncoder.Encode("id:48495349", "FIDO2-NET-LIB-TEST-TPM", "id:F1D00002"), false);
        AddTpmAttStmt(CreateEccPubArea(ecParams, TpmEccCurve.TPM_ECC_NIST_P256), sanExt: sanExt);

        var credential = await MakeAttestationResponseAsync();
        Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
    }

    [Fact]
    public async Task TestTPMAikCertSANManufacturerNotHex()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecParams.Q.X, ecParams.Q.Y);

        var sanExt = new X509Extension("2.5.29.17", TpmSanEncoder.Encode("id:NOTHEX", "FIDO2-NET-LIB-TEST-TPM", "id:F1D00002"), false);
        AddTpmAttStmt(CreateEccPubArea(ecParams, TpmEccCurve.TPM_ECC_NIST_P256), sanExt: sanExt);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid TPM manufacturer found parsing TPM attestation", ex.Message);
    }

    private X509Extension FidoConformanceToolSanExt => new("2.5.29.17", TpmSanEncoder.Encode("id:FFFFF1D0", "FIDO2-NET-LIB-TEST-TPM", "id:F1D00002"), false);

    [Fact]
    public async Task TestTPMAikCertSANFidoConformanceToolManufacturerRefusedByDefault()
    {
        // the conformance tools' simulated TPM is not a TCG-registered vendor, and a production run is not a conformance run
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecParams.Q.X, ecParams.Q.Y);

        AddTpmAttStmt(CreateEccPubArea(ecParams, TpmEccCurve.TPM_ECC_NIST_P256), sanExt: FidoConformanceToolSanExt);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid TPM manufacturer found parsing TPM attestation", ex.Message);

        // and the verifier itself, asked explicitly for the default validation, agrees
        var verifier = AttestationVerifier.Create("tpm");
        ex = await Assert.ThrowsAsync<Fido2VerificationException>(async () => await verifier.VerifyAsync((CborMap)_attestationObject["attStmt"], _authData, _clientDataHash, FidoValidationMode.Default));
        Assert.Equal("Invalid TPM manufacturer found parsing TPM attestation", ex.Message);
    }

    [Fact]
    public async Task TestTPMAikCertSANFidoConformanceToolManufacturerAcceptedOnConformanceRuns()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecParams.Q.X, ecParams.Q.Y);

        AddTpmAttStmt(CreateEccPubArea(ecParams, TpmEccCurve.TPM_ECC_NIST_P256), sanExt: FidoConformanceToolSanExt);

        // the verifier, under conformance validation
        var verifier = AttestationVerifier.Create("tpm");
        var result = await verifier.VerifyAsync((CborMap)_attestationObject["attStmt"], _authData, _clientDataHash, FidoValidationMode.FidoConformance2024);
        Assert.Equal(AttestationType.AttCa, result.Type);

        // and the whole ceremony, which derives that mode from the metadata service reporting a conformance run
        var conformanceMetadataService = new Mock<IMetadataService>(MockBehavior.Strict);
        conformanceMetadataService.Setup(m => m.ConformanceTesting()).Returns(true);
        conformanceMetadataService.Setup(m => m.GetEntryAsync(_aaguid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MetadataBLOBPayloadEntry { AaGuid = _aaguid, StatusReports = [] });

        _attestationObject.Set("authData", new CborByteString(_authData.ToByteArray()));
        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = Base64Url.EncodeToString(_credentialID),
            RawId = _credentialID,
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = _attestationObject.Encode(),
                ClientDataJson = _clientDataJson,
                Transports = [AuthenticatorTransport.Internal]
            },
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
        };
        var options = new CredentialCreateOptions
        {
            Challenge = _challenge,
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
            User = new Fido2User { Name = "testuser", Id = "testuser"u8.ToArray(), DisplayName = "Test User" },
            PubKeyCredParams = [PubKeyCredParam.ES256],
            AuthenticatorSelection = AuthenticatorSelection.Default
        };
        var config = new Fido2Configuration { RPID = rp, RPName = rp, Origins = new HashSet<string> { rp } };

        var credential = await AuthenticatorAttestationResponse.Parse(rawResponse).VerifyAsync(options, config, (_, _) => Task.FromResult(true), conformanceMetadataService.Object, null);

        Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
    }

    [Fact]
    public async Task TestTPMPubAreaTruncated()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecParams.Q.X, ecParams.Q.Y);

        AddTpmAttStmt(CreateEccPubArea(ecParams, TpmEccCurve.TPM_ECC_NIST_P256)[..7]);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Missing or malformed pubArea", ex.Message);
    }

    [Fact]
    public async Task TestTPMCertInfoTruncated()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecParams.Q.X, ecParams.Q.Y);

        AddTpmAttStmt(CreateEccPubArea(ecParams, TpmEccCurve.TPM_ECC_NIST_P256), certInfo: [0xff, 0x54, 0x43, 0x47, 0x80]);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("CertInfo invalid parsing TPM format attStmt", ex.Message);
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


    internal static CredentialPublicKey GetRSACredentialPublicKey(COSE.KeyType type, COSE.Algorithm alg, RSAParameters rsaParams)
    {
        var cpk = new CborMap {
            { COSE.KeyCommonParameter.KeyType, type },
            { COSE.KeyCommonParameter.Alg, alg },
            { COSE.KeyTypeParameter.N, rsaParams.Modulus },
            { COSE.KeyTypeParameter.E, rsaParams.Exponent }
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
