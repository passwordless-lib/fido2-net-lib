using System.Buffers.Text;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test.Attestation;

public class Apple : Fido2Tests.Attestation
{
    public string[] validX5cStrings;
    public Apple()
    {
        validX5cStrings = [
            "MIICRDCCAcmgAwIBAgIGAXUCfWGDMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAxMDA3MDk0NjEyWhcNMjAxMDA4MDk1NjEyWjCBkTFJMEcGA1UEAwxANjEyNzZmYzAyZDNmZThkMTZiMzNiNTU0OWQ4MTkyMzZjODE3NDZhODNmMmU5NGE2ZTRiZWUxYzcwZjgxYjViYzEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR5/lkIu1EpyAk4t1TATSs0DvpmFbmHaYv1naTlPqPm/vsD2qEnDVgE6KthwVqsokNcfb82nXHKFcUjsABKG3W3o1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIJxgAhVAs+GYNN/jfsYkRcieGylPeSzka5QTwyMO84aBMAoGCCqGSM49BAMCA2kAMGYCMQDaHBjrI75xAF7SXzyF5zSQB/Lg9PjTdyye+w7stiqy84K6lmo8d3fIptYjLQx81bsCMQCvC8MSN+aewiaU0bMsdxRbdDerCJJj3xJb3KZwloevJ3daCmCcrZrAPYfLp2kDOsg=",
            "MIICNDCCAbqgAwIBAgIQViVTlcen+0Dr4ijYJghTtjAKBggqhkjOPQQDAzBLMR8wHQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MzgwMVoXDTMwMDMxMzAwMDAwMFowSDEcMBoGA1UEAwwTQXBwbGUgV2ViQXV0aG4gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIMuhy8mFJGBAiW59fzWu2N4tfVfP8sEW8c1mTR1/VSQRN+b/hkhF2XGmh3aBQs41FCDQBpDT7JNES1Ww+HPv8uYkf7AaWCBvvlsvHfIjd2vRqWu4d1RW1r6q5O+nAsmkaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBQm12TZxXjCWmfRp95rEtAbY/HG1zAdBgNVHQ4EFgQU666CxP+hrFtR1M8kYQUAvmO9d4gwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQDdixo0gaX62du052V7hB4UTCe3W4dqQYbCsUdXUDNyJ+/lVEV+9kiVDGMuXEg+cMECMCyKYETcIB/P5ZvDTSkwwUh4Udlg7Wp18etKyr44zSW4l9DIBb7wx/eLB6VxxugOBw=="
        ];
        _attestationObject = new CborMap { { "fmt", "apple" } };
        var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.apple.com, OU=Apple Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using (root = rootRequest.CreateSelfSigned(
            notBefore,
            notAfter))

        using (var ecdsaAtt = ECDsa.Create(eCCurve))
        {
            var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

            byte[] serial = RandomNumberGenerator.GetBytes(12);

            using (X509Certificate2 publicOnly = attRequest.Create(
                root,
                notBefore,
                notAfter,
                serial))
            {
                attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
            }

            var ecParams = ecdsaAtt.ExportParameters(true);

            var cpk = new CborMap {
                { COSE.KeyCommonParameter.KeyType, type },
                { COSE.KeyCommonParameter.Alg, alg },
                { COSE.KeyTypeParameter.X, ecParams.Q.X },
                { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                { COSE.KeyTypeParameter.Crv, crv }
            };

            var x = (byte[])cpk[COSE.KeyTypeParameter.X];
            var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

            _credentialPublicKey = new CredentialPublicKey(cpk);

            var X5c = new CborArray {
                    attestnCert.RawData,
                    root.RawData
                };

            _attestationObject.Add("attStmt", new CborMap { { "x5c", X5c } });
        }
    }

    [Fact]
    public void BundledAppleWebAuthnRootCA_IsIssuerOfGenuineAppleIntermediate()
    {
        // Guards the bundled Apple WebAuthn Root CA against a transcription error: the genuine
        // "Apple WebAuthn CA 1" intermediate (validX5cStrings[1], real Apple data) must chain to it.
        using var intermediate = X509CertificateHelper.CreateFromRawData(Convert.FromBase64String(validX5cStrings[1]));
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(Fido2NetLib.Apple.AppleWebAuthnRootCA);
        chain.ChainPolicy.VerificationTime = intermediate.NotBefore.AddDays(1);

        Assert.True(chain.Build(intermediate));
    }

    [Fact]
    public async Task TestAppleMissingX5c()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAppleX5cNotArray()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborTextString("boomerang"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAppleX5cCountNotOne()
    {
        var emptyX5c = new CborArray { new byte[0], new byte[0] };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", emptyX5c);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAppleX5cValueNotByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborTextString("x"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAppleX5cValueZeroLengthByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborArray { new byte[0] });
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAppleCertMissingExtension()
    {
        var invalidX5cStrings = validX5cStrings;
        var invalidCert = Convert.FromBase64String(invalidX5cStrings[0]);
        invalidCert[424] = 0x42;
        invalidX5cStrings[0] = Convert.ToBase64String(invalidCert);

        var trustPath = invalidX5cStrings
            .Select(x => X509CertificateHelper.CreateFromRawData(Convert.FromBase64String(x)))
            .ToArray();

        var x5c = new CborArray {
            trustPath[0].RawData,
            trustPath[1].RawData
        };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", x5c);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Extension with OID 1.2.840.113635.100.8.2 not found on Apple attestation credCert", ex.Message);
    }

    [Fact]
    public async Task TestAppleCertCorruptExtension()
    {
        var invalidX5cStrings = validX5cStrings;
        var invalidCert = Convert.FromBase64String(invalidX5cStrings[0]);
        invalidCert[429] = 0x03;
        invalidX5cStrings[0] = Convert.ToBase64String(invalidCert);

        var trustPath = invalidX5cStrings
            .Select(x => X509CertificateHelper.CreateFromRawData(Convert.FromBase64String(x)))
            .ToArray();

        var x5c = new CborArray {
            trustPath[0].RawData,
            trustPath[1].RawData
        };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", x5c);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Apple attestation extension has invalid data", ex.Message);
    }

    [Fact]
    public async Task TestAppleInvalidNonce()
    {
        var trustPath = validX5cStrings
            .Select(x => X509CertificateHelper.CreateFromRawData(Convert.FromBase64String(x)))
            .ToArray();

        var x5c = new CborArray {
            trustPath[0].RawData,
            trustPath[1].RawData
        };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", x5c);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Mismatch between nonce and credCert attestation extension in Apple attestation", ex.Message);
    }

    [Fact]
    public async Task TestApplePublicKeyMismatch()
    {
        // A credCert whose public key differs from the attested credential public key must be rejected. The
        // nonce still matches, so verification reaches the public-key comparison before the chain check.
        using var credCertKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        _credentialPublicKey = new CredentialPublicKey(otherKey, COSE.Algorithm.ES256);

        byte[] nonce = SHA256.HashData([.. _authData.ToByteArray(), .. _clientDataHash]);
        (X509Certificate2 root, X509Certificate2 credCert) = BuildAppleCredentialChain(credCertKey, nonce);
        using (root)
        using (credCert)
        {
            ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborArray { credCert.RawData, root.RawData });
            AppleWebAuthnRootOverride = root;

            var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
            Assert.Equal("Credential public key in Apple attestation does not match subject public key of credCert", ex.Message);
        }
    }

    [Fact]
    public async Task TestAppleValidChainSucceedsWhenRootInjected()
    {
        // A well-formed apple attestation whose chain terminates at the configured root verifies successfully.
        using var credCertKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _credentialPublicKey = new CredentialPublicKey(credCertKey, COSE.Algorithm.ES256);

        byte[] nonce = SHA256.HashData([.. _authData.ToByteArray(), .. _clientDataHash]);
        (X509Certificate2 root, X509Certificate2 credCert) = BuildAppleCredentialChain(credCertKey, nonce);
        using (root)
        using (credCert)
        {
            ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborArray { credCert.RawData, root.RawData });
            AppleWebAuthnRootOverride = root;

            var credential = await MakeAttestationResponseAsync();

            Assert.Equal("apple", credential.AttestationFormat);
            Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
            // 8.8 step 7: attestation type Anonymization CA
            Assert.Equal("anonca", credential.AttestationType);
        }
    }

    [Fact]
    public async Task TestAppleChainNotAnchoredToConfiguredRootIsRejected()
    {
        // Nonce and public key match, but the chain does not terminate at the configured (Apple) root, so a
        // self-signed credCert can no longer masquerade as a genuine Apple attestation.
        using var credCertKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _credentialPublicKey = new CredentialPublicKey(credCertKey, COSE.Algorithm.ES256);

        byte[] nonce = SHA256.HashData([.. _authData.ToByteArray(), .. _clientDataHash]);
        (X509Certificate2 root, X509Certificate2 credCert) = BuildAppleCredentialChain(credCertKey, nonce);

        using var otherRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var otherRootRequest = new CertificateRequest("CN=Unrelated Root CA", otherRootKey, HashAlgorithmName.SHA256);
        otherRootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

        using (root)
        using (credCert)
        using (var unrelatedRoot = otherRootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)))
        {
            ((CborMap)_attestationObject["attStmt"]).Set("x5c", new CborArray { credCert.RawData, root.RawData });
            AppleWebAuthnRootOverride = unrelatedRoot; // a different root than the one that signed credCert

            var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
            Assert.StartsWith("Failed to build chain in Apple attestation", ex.Message);
        }
    }

    private (X509Certificate2 root, X509Certificate2 credCert) BuildAppleCredentialChain(ECDsa credCertKey, byte[] nonce)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Test Apple WebAuthn Root CA", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Apple credCert extension 1.2.840.113635.100.8.2 is SEQUENCE { [1] { OCTET STRING nonce } }.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            writer.WriteOctetString(nonce);
        }
        var nonceExtension = new X509Extension("1.2.840.113635.100.8.2", writer.Encode(), false);

        var credRequest = new CertificateRequest("CN=attest.apple.com", credCertKey, HashAlgorithmName.SHA256);
        credRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        credRequest.CertificateExtensions.Add(nonceExtension);

        var credCert = credRequest.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(12));

        return (root, credCert);
    }
}
