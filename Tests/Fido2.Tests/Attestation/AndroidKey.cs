using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test.Attestation;

public class AndroidKey : Fido2Tests.Attestation
{
    public byte[] EncodeAttestationRecord()
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);

        using (writer.PushSequence()) // KeyDescription
        {
            writer.WriteInteger(3); // attestationVersion
            writer.WriteNull(); // attestationSecurityLevel
            writer.WriteInteger(2); // keymasterVersion
            writer.WriteNull(); // keymasterSecurityLevel
            writer.WriteOctetString(_clientDataHash); // attestationChallenge
            writer.WriteOctetString(_credentialID); // uniqueId
            using (writer.PushSequence()) // softwareEnforced
            {
                writer.WriteNull();
            }
            using (writer.PushSequence()) // teeEnforced
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1))) // purpose
                {
                    using (writer.PushSetOf())
                    {
                        writer.WriteInteger(2); // KM_PURPOSE_SIGN
                    }
                }
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 702))) // origin
                {
                    writer.WriteInteger(0); // KM_ORIGIN_GENERATED
                }
            }
        }
        return writer.Encode();
    }

    public AndroidKey()
    {
        _attestationObject = new CborMap { { "fmt", "android-key" } };
        X509Certificate2 attestnCert;
        using var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

        attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", EncodeAttestationRecord(), false));

        using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
        {
            var X5c = new CborArray { attestnCert.RawData };

            byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

            _attestationObject.Add("attStmt", new CborMap {
                { "alg", COSE.Algorithm.ES256 },
                { "x5c", X5c },
                { "sig", signature }
            });
        }
    }

    [Fact]
    public async Task TestAndroidKey()
    {
        var credential = await MakeAttestationResponseAsync();
        Assert.Equal(_aaguid, credential.AaGuid);
        Assert.Equal(_signCount, credential.SignCount);
        Assert.Equal("android-key", credential.AttestationFormat);
        Assert.Equal("basic", credential.AttestationType);
        Assert.Equal(_credentialID, credential.Id);
        Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
        Assert.Equal("Test User", credential.User.DisplayName);
        Assert.Equal("testuser"u8.ToArray(), credential.User.Id);
        Assert.Equal("testuser", credential.User.Name);
        Assert.Equal(new[] { AuthenticatorTransport.Internal }, credential.Transports);
    }

    [Fact]
    public async Task TestAndroidKeySigNull()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("sig", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyAttStmtEmpty()
    {
        _attestationObject.Set("attStmt", new CborMap { });
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Attestation format android-key must have attestation statement", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeySigNotByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("sig", new CborTextString("walrus"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeySigByteStringZeroLen()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("sig", new CborByteString(Array.Empty<byte>()));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyMissingX5c()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message);
    }
    [Fact]
    public async Task TestAndroidKeyX5cNotArray()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborTextString("boomerang"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cValueNotByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborTextString("x"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cValueZeroLengthByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborArray { Array.Empty<byte>() });
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyInvalidPublicKey()
    {
        var attestnCert = (byte[])_attestationObject["attStmt"]["x5c"][0];
        attestnCert[0] ^= 0xff;
        var X5c = new CborArray { attestnCert };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", X5c);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.StartsWith("Failed to extract public key from android key: ", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertNotEc()
    {
        _attestationObject = new CborMap { { "fmt", "android-key" } };
        using var rsaAtt = RSA.Create(2048);
        var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", rsaAtt, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", EncodeAttestationRecord(), false));

        using X509Certificate2 attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2));

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", COSE.Algorithm.RS256 },
            { "x5c", new CborArray { attestnCert.RawData } },
            { "sig", new byte[256] }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation public key", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyMissingAlg()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Remove("alg");
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation algorithm", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyAlgNull()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("alg", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation algorithm", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyAlgNaN()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("alg", new CborTextString("invalid alg"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation algorithm", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyAlgNotInMap()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("alg", new CborInteger(-1));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Unrecognized COSE algorithm value", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeySigNotASN1()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("sig", new CborByteString([0xf1, 0xd0]));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid android-key attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyBadSig()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        var sig = (byte[])attStmt["sig"];
        sig[^1] ^= 0xff;
        attStmt.Set("sig", new CborByteString(sig));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Same(Fido2ErrorMessages.InvalidAndroidKeyAttestationSignature, ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertMissingAttestationRecordExt()
    {
        _attestationObject = new CborMap { { "fmt", "android-key" } };
        X509Certificate2 attestnCert;
        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
            {
                var X5c = new CborArray { attestnCert.RawData };

                byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                _attestationObject.Add("attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Android key attestation certificate contains no AttestationRecord extension", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertAttestationRecordExtMalformed()
    {
        _attestationObject = new CborMap { { "fmt", "android-key" } };
        X509Certificate2 attestnCert;
        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", new byte[] { 0x0 }, false));

            using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
            {
                var x5c = new CborArray { attestnCert.RawData };

                byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                _attestationObject.Add("attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", x5c },
                    { "sig", signature }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Malformed android key AttestationRecord extension verifying android key attestation certificate extension", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertAttestationRecordChallengeMismatch()
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);

        using (writer.PushSequence()) // KeyDescription
        {
            writer.WriteInteger(3); // attestationVersion
            writer.WriteNull();
            writer.WriteInteger(2);
            writer.WriteNull();
            writer.WriteOctetString(SHA256.HashData("some other client data"u8)); // attestationChallenge
            writer.WriteOctetString(_credentialID);
            using (writer.PushSequence())
            {
                writer.WriteNull();
            }
            using (writer.PushSequence())
            {
                writer.WriteNull();
            }
        }
        var attRecord = writer.Encode();

        _attestationObject = new CborMap { { "fmt", "android-key" } };
        X509Certificate2 attestnCert;
        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

            using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
            {
                var X5c = new CborArray { attestnCert.RawData };

                byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                _attestationObject.Add("attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        // A well-formed record with the wrong challenge is a mismatch, not a malformed record
        Assert.Equal("Mismatch between attestationChallenge and hashedClientDataJson verifying android key attestation certificate extension", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertInvalidPublicKey()
    {
        _attestationObject = new CborMap { { "fmt", "android-key" } };
        using var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

        attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", EncodeAttestationRecord(), false));

        using var attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2));

        // Knock the subjectPublicKey off the curve: the SPKI BIT STRING (03 42 00) wraps the uncompressed point (04 X Y)
        byte[] rawData = attestnCert.RawData;
        int point = rawData.AsSpan().IndexOf(new byte[] { 0x03, 0x42, 0x00, 0x04 }) + 4;
        rawData[point] ^= 0xff;

        _attestationObject.Add("attStmt", new CborMap {
            { "alg", COSE.Algorithm.ES256 },
            { "x5c", new CborArray { rawData } },
            { "sig", SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt) }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.InvalidAndroidKeyAttestationPublicKey, ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertAttestationRecordAllApplicationsSoftware()
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);

        using (writer.PushSequence()) // KeyDescription
        {
            writer.WriteInteger(3); // attestationVersion
            writer.WriteNull();
            writer.WriteInteger(2);
            writer.WriteNull();
            writer.WriteOctetString(_clientDataHash);
            writer.WriteOctetString(_credentialID);
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 600)))
                {
                    writer.WriteNull();
                }
            }
            using (writer.PushSequence())
            {
                writer.WriteNull();
            }
        }
        var attRecord = writer.Encode();

        _attestationObject = new CborMap { { "fmt", "android-key" } };
        X509Certificate2 attestnCert;
        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

            using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
            {
                var X5c = new CborArray { attestnCert.RawData };

                byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                _attestationObject.Add("attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Found all applications field in android key attestation certificate extension", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertAttestationRecordAllApplicationsTee()
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);

        using (writer.PushSequence()) // KeyDescription
        {
            writer.WriteInteger(3); // attestationVersion
            writer.WriteNull();
            writer.WriteInteger(2);
            writer.WriteNull();
            writer.WriteOctetString(_clientDataHash);
            writer.WriteOctetString(_credentialID);
            using (writer.PushSequence())
            {
                writer.WriteNull();
            }
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 600)))
                {
                    writer.WriteNull();
                }
            }
        }
        var attRecord = writer.Encode();

        _attestationObject = new CborMap { { "fmt", "android-key" } };
        X509Certificate2 attestnCert;
        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

            using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
            {
                var X5c = new CborArray { attestnCert.RawData };

                byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                _attestationObject.Add("attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Found all applications field in android key attestation certificate extension", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertAttestationRecordOriginSoftware()
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);

        using (writer.PushSequence()) // KeyDescription
        {
            writer.WriteInteger(3); // attestationVersion
            writer.WriteNull();
            writer.WriteInteger(2);
            writer.WriteNull();
            writer.WriteOctetString(_clientDataHash);
            writer.WriteOctetString(_credentialID);
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 702)))
                {
                    writer.WriteInteger(1);
                }
            }
            using (writer.PushSequence())
            {
                writer.WriteNull();
            }
        }
        var attRecord = writer.Encode();

        _attestationObject = new CborMap { { "fmt", "android-key" } };
        X509Certificate2 attestnCert;
        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

            using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
            {
                var X5c = new CborArray { attestnCert.RawData };

                byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                _attestationObject.Add("attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertAttestationRecordOriginTee()
    {
        AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);

        using (writer.PushSequence()) // KeyDescription
        {
            writer.WriteInteger(3); // attestationVersion
            writer.WriteNull();
            writer.WriteInteger(2);
            writer.WriteNull();
            writer.WriteOctetString(_clientDataHash);
            writer.WriteOctetString(_credentialID);
            using (writer.PushSequence())
            {
                writer.WriteNull();
            }
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 702)))
                {
                    writer.WriteInteger(1);
                }
            }
        }
        var attRecord = writer.Encode();

        _attestationObject = new CborMap { { "fmt", "android-key" } };
        X509Certificate2 attestnCert;
        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

            using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
            {
                var X5c = new CborArray { attestnCert.RawData };

                byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                _attestationObject.Add("attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertAttestationRecordPurposeSoftware()
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);

        using (writer.PushSequence()) // KeyDescription
        {
            writer.WriteInteger(3); // attestationVersion
            writer.WriteNull();
            writer.WriteInteger(2);
            writer.WriteNull();
            writer.WriteOctetString(_clientDataHash);
            writer.WriteOctetString(_credentialID);
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    using (writer.PushSetOf())
                    {
                        writer.WriteInteger(1);
                    }
                }
            }
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 702))) // valid origin so the purpose check is reached
                {
                    writer.WriteInteger(0);
                }
            }
        }
        var attRecord = writer.Encode();

        _attestationObject = new CborMap { { "fmt", "android-key" } };
        X509Certificate2 attestnCert;
        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

            using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
            {
                var X5c = new CborArray { attestnCert.RawData };

                byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                _attestationObject.Add("attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cCertAttestationRecordPurposeTee()
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);

        using (writer.PushSequence()) // KeyDescription
        {
            writer.WriteInteger(3); // attestationVersion
            writer.WriteNull();
            writer.WriteInteger(2);
            writer.WriteNull();
            writer.WriteOctetString(_clientDataHash);
            writer.WriteOctetString(_credentialID);
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 702))) // valid origin so the purpose check is reached
                {
                    writer.WriteInteger(0);
                }
            }
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    using (writer.PushSetOf())
                    {
                        writer.WriteInteger(1);
                    }
                }
            }
        }
        var attRecord = writer.Encode();

        _attestationObject = new CborMap { { "fmt", "android-key" } };
        X509Certificate2 attestnCert;
        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

            using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
            {
                var X5c = new CborArray { attestnCert.RawData };

                byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                _attestationObject.Add("attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension", ex.Message);
    }

    private async Task<Fido2VerificationException> RunWithAttestationRecordAsync(byte[] attRecord)
    {
        _attestationObject = new CborMap { { "fmt", "android-key" } };

        using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

            attRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.11129.2.1.17", attRecord, false));

            using var attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2));

            var X5c = new CborArray { attestnCert.RawData };

            byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

            _attestationObject.Add("attStmt", new CborMap {
                { "alg", COSE.Algorithm.ES256 },
                { "x5c", X5c },
                { "sig", signature }
            });
        }

        return await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
    }

    private byte[] EncodeAttestationRecord(Action<AsnWriter> writeSoftwareEnforced, Action<AsnWriter> writeTeeEnforced)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);

        using (writer.PushSequence()) // KeyDescription
        {
            writer.WriteInteger(3); // attestationVersion
            writer.WriteNull(); // attestationSecurityLevel
            writer.WriteInteger(2); // keymasterVersion
            writer.WriteNull(); // keymasterSecurityLevel
            writer.WriteOctetString(_clientDataHash); // attestationChallenge
            writer.WriteOctetString(_credentialID); // uniqueId
            using (writer.PushSequence()) // softwareEnforced
            {
                writeSoftwareEnforced(writer);
            }
            using (writer.PushSequence()) // teeEnforced
            {
                writeTeeEnforced(writer);
            }
        }

        return writer.Encode();
    }

    [Fact]
    public async Task TestAndroidKeyOriginMissingIsRejected()
    {
        // A KeyMint authorization list with a valid purpose but no origin (702) must fail closed: an absent
        // origin is not evidence the key was generated inside secure hardware rather than imported.
        byte[] attRecord = EncodeAttestationRecord(
            w => w.WriteNull(),
            w =>
            {
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1))) // purpose
                using (w.PushSetOf())
                {
                    w.WriteInteger(2); // KM_PURPOSE_SIGN
                }
            });

        var ex = await RunWithAttestationRecordAsync(attRecord);
        Assert.Equal("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyPurposeMissingIsRejected()
    {
        // A KeyMint authorization list with a valid origin but no purpose (1) must fail closed: an absent
        // purpose is not evidence the key may be used to sign.
        byte[] attRecord = EncodeAttestationRecord(
            w => w.WriteNull(),
            w =>
            {
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 702))) // origin
                {
                    w.WriteInteger(0); // KM_ORIGIN_GENERATED
                }
            });

        var ex = await RunWithAttestationRecordAsync(attRecord);
        Assert.Equal("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension", ex.Message);
    }
}
