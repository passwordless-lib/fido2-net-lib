using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test.Attestation;

public class Packed : Fido2Tests.Attestation
{
    public Packed()
    {
        _attestationObject = new CborMap { { "fmt", "packed" } };
    }

    [Fact]
    public async Task TestSelf()
    {
        foreach (var (type, alg, crv) in Fido2Tests._validCOSEParameters)
        {
            // No support for P256K on OSX
            if (OperatingSystem.IsMacOS() && crv is COSE.EllipticCurve.P256K)
                continue;

            var signature = SignData(type, alg, crv);

            _attestationObject.Set("attStmt", new CborMap {
                { "alg", alg },
                { "sig", signature }
            });

            var res = await MakeAttestationResponseAsync();

            Assert.Equal(string.Empty, res.ErrorMessage);
            Assert.Equal("ok", res.Status);
            Assert.Equal(_aaguid, res.Result.AaGuid);
            Assert.Equal(_signCount, res.Result.SignCount);
            Assert.Equal("packed", res.Result.AttestationFormat);
            Assert.Equal(_credentialID, res.Result.Id);
            Assert.Null(res.Result.ErrorMessage);
            Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
            Assert.Null(res.Result.Status);
            Assert.Equal("Test User", res.Result.User.DisplayName);
            Assert.Equal("testuser"u8.ToArray(), res.Result.User.Id);
            Assert.Equal("testuser", res.Result.User.Name);
            _attestationObject = new CborMap { { "fmt", "packed" } };
        }
    }

    [Fact]
    public async Task TestSelfAlgMismatch()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];

        byte[] signature = SignData(type, alg, curve);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", COSE.Algorithm.ES384 },
            { "sig", signature }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Algorithm mismatch between credential public key and authenticator data in self attestation statement", ex.Message);
    }

    [Fact]
    public async Task TestSelfBadSig()
    {
        var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
        var signature = SignData(type, alg, crv);
        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", new byte[] { 0x30, 0x45, 0x02, 0x20, 0x11, 0x9b, 0x6f, 0xa8, 0x1c, 0xe1, 0x75, 0x9e, 0xbe, 0xf1, 0x52, 0xa6, 0x99, 0x40, 0x5e, 0xd6, 0x6a, 0xcc, 0x01, 0x33, 0x65, 0x18, 0x05, 0x00, 0x96, 0x28, 0x29, 0xbe, 0x85, 0x57, 0xb7, 0x1d, 0x02, 0x21, 0x00, 0x94, 0x50, 0x1d, 0xf1, 0x90, 0x03, 0xa4, 0x4d, 0xa4, 0xdf, 0x9f, 0xbb, 0xb5, 0xe4, 0xce, 0x91, 0x6b, 0xc3, 0x90, 0xe8, 0x38, 0x99, 0x66, 0x4f, 0xa5, 0xc4, 0x0c, 0xf3, 0xed, 0xe3, 0xda, 0x83 } }
        });
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Failed to validate signature", ex.Message);
    }

    [Fact]
    public async Task TestMissingAlg()
    {
        var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
        var signature = SignData(type, alg, crv);
        _attestationObject.Add("attStmt", new CborMap { { "sig", signature } });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid packed attestation algorithm", ex.Message);
    }

    [Fact]
    public async Task TestEcdaaKeyIdPresent()
    {
        var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
        var signature = SignData(type, alg, crv);
        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "ecdaaKeyId", signature }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.UnimplementedAlgorithm, ex.Code);
        Assert.Equal(Fido2ErrorMessages.UnimplementedAlgorithm_Ecdaa_Packed, ex.Message);
    }

    [Fact]
    public async Task TestEmptyAttStmt()
    {
        var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
        var signature = SignData(type, alg, crv);
        _attestationObject.Add("attStmt", new CborMap { });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Attestation format packed must have attestation statement", ex.Message);
    }

    [Fact]
    public async Task TestAlgNaN()
    {
        var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
        var signature = SignData(type, alg, crv);
        _attestationObject.Add("attStmt", new CborMap {
            { "alg", "invalid alg" },
            { "sig", signature }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid packed attestation algorithm", ex.Message);
    }

    [Fact]
    public async Task TestSigNull()
    {
        var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
        var signature = SignData(type, alg, crv);
        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", CborNull.Instance }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid packed attestation signature", ex.Message);
    }

    [Fact]
    public void TestSigNotByteString()
    {
        var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
        var signature = SignData(type, alg, crv);
        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", "walrus" }
        });
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid packed attestation signature", ex.Result.Message);
    }

    [Fact]
    public async Task TestSigByteStringZeroLen()
    {
        var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
        var signature = SignData(type, alg, crv);
        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", Array.Empty<byte>() }
        });
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid packed attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestFull()
    {
        foreach (var (type, alg, curve) in Fido2Tests._validCOSEParameters)
        {
            if (type is COSE.KeyType.OKP)
            {
                return;
            }

            // No support for P256K on OSX
            if (OperatingSystem.IsMacOS() && curve == COSE.EllipticCurve.P256K)
                return;

            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            MakeNewCredentialResult res = null;

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
                            case COSE.EllipticCurve.P256K:
                                if (OperatingSystem.IsMacOS())
                                {
                                    // see https://github.com/dotnet/runtime/issues/47770
                                    throw new PlatformNotSupportedException($"No support currently for secP256k1 on MacOS");
                                }
                                eCCurve = ECCurve.CreateFromFriendlyName("secP256k1");
                                break;
                        }

                        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
                        using var ecdsaAtt = ECDsa.Create(eCCurve);
                        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                        attRequest.CertificateExtensions.Add(notCAExt);
                        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

                        byte[] serial = RandomNumberGenerator.GetBytes(12);

                        using (X509Certificate2 publicOnly = attRequest.Create(
                            root,
                            notBefore,
                            notAfter,
                            serial))
                        {
                            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                        }

                        var x5c = new CborArray {
                            attestnCert.RawData,
                            root.RawData
                        };

                        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                        _attestationObject.Set("attStmt", new CborMap {
                            { "alg", alg },
                            { "sig", signature },
                            { "x5c", x5c }
                        });

                        res = await MakeAttestationResponseAsync();
                    }
                    break;
                case COSE.KeyType.RSA:
                    using (RSA rsaRoot = RSA.Create())
                    {
                        var padding = RSASignaturePadding.Pss;

                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
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

                        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
                        using var rsaAtt = RSA.Create();
                        var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                        attRequest.CertificateExtensions.Add(notCAExt);
                        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

                        byte[] serial = RandomNumberGenerator.GetBytes(12);

                        using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
                        {
                            attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                        }

                        var x5c = new CborArray { attestnCert.RawData, root.RawData };

                        byte[] signature = SignData(type, alg, COSE.EllipticCurve.Reserved, rsa: rsaAtt);

                        _attestationObject.Set("attStmt", new CborMap {
                            { "alg", alg },
                            { "sig", signature },
                            { "x5c", x5c }
                        });

                        res = await MakeAttestationResponseAsync();
                    }
                    break;
                case COSE.KeyType.OKP:
                    {
                        var avr = new VerifyAssertionResult
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
            Assert.Equal(_aaguid, res.Result.AaGuid);
            Assert.Equal(_signCount, res.Result.SignCount);
            Assert.Equal("packed", res.Result.AttestationFormat);
            Assert.Equal(_credentialID, res.Result.Id);
            Assert.Null(res.Result.ErrorMessage);
            Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
            Assert.Null(res.Result.Status);
            Assert.Equal("Test User", res.Result.User.DisplayName);
            Assert.Equal("testuser"u8.ToArray(), res.Result.User.Id);
            Assert.Equal("testuser", res.Result.User.Name);
            _attestationObject = new CborMap { { "fmt", "packed" } };
        }
    }

    [Fact]
    public void TestFullMissingX5c()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);

        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var X5c = new CborArray { attestnCert.RawData, root.RawData };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "x5c", CborNull.Instance }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Same(Fido2ErrorMessages.MalformedX5c_PackedAttestation, ex.Result.Message);
    }

    [Fact]
    public void TestFullX5cNotArray()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);

        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);

        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            root,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var X5c = new CborArray { attestnCert.RawData, root.RawData };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "x5c", "boomerang" }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Same(Fido2ErrorMessages.MalformedX5c_PackedAttestation, ex.Result.Message);
    }

    [Fact]
    public void TestFullX5cCountNotOne()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);

        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray { attestnCert.RawData, root.RawData };

        var signature = SignData(type, alg, COSE.EllipticCurve.Reserved, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature},
            { "x5c", new CborArray { Array.Empty<byte>(), Array.Empty<byte>() } }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Malformed x5c cert found in packed attestation statement", ex.Result.Message);
    }

    [Fact]
    public void TestFullX5cValueNotByteString()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray { attestnCert.RawData, root.RawData };

        byte[] signature = SignData(type, alg, COSE.EllipticCurve.Reserved, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "x5c", new CborArray { "x" } }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Malformed x5c cert found in packed attestation statement", ex.Result.Message);
    }

    [Fact]
    public void TestFullX5cValueZeroLengthByteString()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray { attestnCert.RawData, root.RawData };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "x5c", new CborArray { Array.Empty<byte>() } }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Malformed x5c cert found in packed attestation statement", ex.Result.Message);
    }

    [Fact]
    public void TestFullX5cCertExpired()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-7);
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);

        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            root,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var X5c = new CborArray { attestnCert.RawData, root.RawData };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "x5c", X5c }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Packed signing certificate expired or not yet valid", ex.Result.Message);
    }

    [Fact]
    public void TestFullX5cCertNotYetValid()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(1);
        DateTimeOffset notAfter = notBefore.AddDays(7);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            root,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            root.RawData
        };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "x5c", x5c }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Packed signing certificate expired or not yet valid", ex.Result.Message);
    }

    [Fact]
    public void TestFullInvalidAlg()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);

        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray { attestnCert.RawData, root.RawData };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", 42 },
            { "sig", signature },
            { "x5c", x5c }
        });

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Missing or unknown alg 42", ex.Result.Message);
    }

    [Fact]
    public void TestFullInvalidSig()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            root.RawData
        };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", new byte[] { 0x30, 0x45, 0x02, 0x20, 0x11, 0x9b, 0x6f, 0xa8, 0x1c, 0xe1, 0x75, 0x9e, 0xbe, 0xf1, 0x52, 0xa6, 0x99, 0x40, 0x5e, 0xd6, 0x6a, 0xcc, 0x01, 0x33, 0x65, 0x18, 0x05, 0x00, 0x96, 0x28, 0x29, 0xbe, 0x85, 0x57, 0xb7, 0x1d, 0x02, 0x21, 0x00, 0x94, 0x50, 0x1d, 0xf1, 0x90, 0x03, 0xa4, 0x4d, 0xa4, 0xdf, 0x9f, 0xbb, 0xb5, 0xe4, 0xce, 0x91, 0x6b, 0xc3, 0x90, 0xe8, 0x38, 0x99, 0x66, 0x4f, 0xa5, 0xc4, 0x0c, 0xf3, 0xed, 0xe3, 0xda, 0x83 } },
            { "x5c", x5c }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid full packed signature", ex.Result.Message);
    }

    [Fact]
    public void TestFullAttCertNotV3()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);

        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

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

        var x5c = new CborArray { rawAttestnCert, root.RawData };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature},
            { "x5c", x5c }
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
            Assert.Equal("Packed x5c attestation certificate not V3", ex.Result.Message);
        }
    }

    [Fact]
    public async Task TestFullAttCertSubject()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Not Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);
        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            root,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            root.RawData
        };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "x5c", x5c }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.InvalidAttestationCertSubject, ex.Message);
    }

    [Fact]
    public async void TestAttCertSubjectCommaAsync()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("""CN=Testing, OU=Authenticator Attestation, O="FIDO2-NET-LIB, Inc.", C=US""");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);

        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);

        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            root.RawData
        };

        var signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "x5c", x5c },
        });

        var res = await MakeAttestationResponseAsync();
        Assert.Equal(string.Empty, res.ErrorMessage);
        Assert.Equal("ok", res.Status);
    }

    [Fact]
    public async Task TestFullAttCertAaguidNotMatchAuthdata()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);
        using var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(notCAExt);

        var notAsnEncodedAaguid = _asnEncodedAaguid;
        notAsnEncodedAaguid[3] = 0x42;
        var notIdFidoGenCeAaguidExt = new X509Extension(oidIdFidoGenCeAaGuid, _asnEncodedAaguid, false);
        attRequest.CertificateExtensions.Add(notIdFidoGenCeAaguidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            root.RawData
        };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "x5c", x5c }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("aaguid present in packed attestation cert exts but does not match aaguid from authData", ex.Message);
    }

    [Fact]
    public void TestFullAttCertCAFlagSet()
    {
        (COSE.KeyType type, COSE.Algorithm alg, COSE.EllipticCurve curve) = Fido2Tests._validCOSEParameters[0];

        X509Certificate2 attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);

        using var ecdsaAtt = ECDsa.Create(eCCurve);
        var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
        attRequest.CertificateExtensions.Add(caExt);

        attRequest.CertificateExtensions.Add(idFidoGenCeAaGuidExt);

        byte[] serial = RandomNumberGenerator.GetBytes(12);

        using (X509Certificate2 publicOnly = attRequest.Create(
            root,
            notBefore,
            notAfter,
            serial))
        {
            attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
        }

        var x5c = new CborArray {
            attestnCert.RawData,
            root.RawData
        };

        byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", alg },
            { "sig", signature },
            { "x5c", x5c }
        });

        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Attestation certificate has CA cert flag present", ex.Result.Message);
    }
}
