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
                writer.WriteNull();
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
    public async void TestAndroidKey()
    {
        var res = await MakeAttestationResponseAsync();
        Assert.Equal(string.Empty, res.ErrorMessage);
        Assert.Equal("ok", res.Status);
        Assert.Equal(_aaguid, res.Result.AaGuid);
        Assert.Equal(_signCount, res.Result.SignCount);
        Assert.Equal("android-key", res.Result.AttestationFormat);
        Assert.Equal(_credentialID, res.Result.Id);
        Assert.Null(res.Result.ErrorMessage);
        Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
        Assert.Null(res.Result.Status);
        Assert.Equal("Test User", res.Result.User.DisplayName);
        Assert.Equal("testuser"u8.ToArray(), res.Result.User.Id);
        Assert.Equal("testuser", res.Result.User.Name);
    }

    [Fact]
    public async Task TestAndroidKeySigNull()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("sig", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyAttStmtEmpty()
    {
        _attestationObject.Set("attStmt", new CborMap { });
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Attestation format android-key must have attestation statement", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeySigNotByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("sig", new CborTextString("walrus"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeySigByteStringZeroLen()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("sig", new CborByteString(Array.Empty<byte>()));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation signature", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyMissingX5c()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message);
    }
    [Fact]
    public async Task TestAndroidKeyX5cNotArray()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborTextString("boomerang"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cValueNotByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborTextString("x"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyX5cValueZeroLengthByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborArray { Array.Empty<byte>() });
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message);
    }

    [Fact]
    public void TestAndroidKeyInvalidPublicKey()
    {
        var attestnCert = (byte[])_attestationObject["attStmt"]["x5c"][0];
        attestnCert[0] ^= 0xff;
        var X5c = new CborArray { attestnCert };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", X5c);
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.StartsWith("Failed to extract public key from android key: ", ex.Result.Message);
    }

    [Fact]
    public async Task TestAndroidKeyMissingAlg()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Remove("alg");
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation algorithm", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyAlgNull()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("alg", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation algorithm", ex.Message);
    }

    [Fact]
    public async Task TestAndroidKeyAlgNaN()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("alg", new CborTextString("invalid alg"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Invalid android-key attestation algorithm", ex.Message);
    }

    [Fact]
    public void TestAndroidKeyAlgNotInMap()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("alg", new CborInteger(-1));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Unrecognized COSE algorithm value", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidKeySigNotASN1()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("sig", new CborByteString(new byte[] { 0xf1, 0xd0 }));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Failed to decode android key attestation signature from ASN.1 encoded form", ex.Result.Message);

        var innerException = (AsnContentException)ex.Result.InnerException;
        Assert.Equal("The ASN.1 value is invalid.", innerException.Message);
    }

    [Fact]
    public async Task TestAndroidKeyBadSig()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        var sig = (byte[])attStmt["sig"];
        sig[^1] ^= 0xff;
        attStmt.Set("sig", new CborByteString(sig));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Same(Fido2ErrorMessages.InvalidAndroidKeyAttestationSignature, ex.Message);
    }

    [Fact]
    public void TestAndroidKeyX5cCertMissingAttestationRecordExt()
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
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Android key attestation certificate contains no AttestationRecord extension", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidKeyX5cCertAttestationRecordExtMalformed()
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
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Malformed android key AttestationRecord extension verifying android key attestation certificate extension", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidKeyX5cCertAttestationRecordAllApplicationsSoftware()
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
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Found all applications field in android key attestation certificate extension", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidKeyX5cCertAttestationRecordAllApplicationsTee()
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
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Found all applications field in android key attestation certificate extension", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidKeyX5cCertAttestationRecordOriginSoftware()
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
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidKeyX5cCertAttestationRecordOriginTee()
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
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidKeyX5cCertAttestationRecordPurposeSoftware()
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
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidKeyX5cCertAttestationRecordPurposeTee()
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
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension", ex.Result.Message);
    }
}
