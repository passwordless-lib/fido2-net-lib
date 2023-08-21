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
        validX5cStrings = new[] {
            "MIICRDCCAcmgAwIBAgIGAXUCfWGDMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAxMDA3MDk0NjEyWhcNMjAxMDA4MDk1NjEyWjCBkTFJMEcGA1UEAwxANjEyNzZmYzAyZDNmZThkMTZiMzNiNTU0OWQ4MTkyMzZjODE3NDZhODNmMmU5NGE2ZTRiZWUxYzcwZjgxYjViYzEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR5/lkIu1EpyAk4t1TATSs0DvpmFbmHaYv1naTlPqPm/vsD2qEnDVgE6KthwVqsokNcfb82nXHKFcUjsABKG3W3o1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIJxgAhVAs+GYNN/jfsYkRcieGylPeSzka5QTwyMO84aBMAoGCCqGSM49BAMCA2kAMGYCMQDaHBjrI75xAF7SXzyF5zSQB/Lg9PjTdyye+w7stiqy84K6lmo8d3fIptYjLQx81bsCMQCvC8MSN+aewiaU0bMsdxRbdDerCJJj3xJb3KZwloevJ3daCmCcrZrAPYfLp2kDOsg=",
            "MIICNDCCAbqgAwIBAgIQViVTlcen+0Dr4ijYJghTtjAKBggqhkjOPQQDAzBLMR8wHQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MzgwMVoXDTMwMDMxMzAwMDAwMFowSDEcMBoGA1UEAwwTQXBwbGUgV2ViQXV0aG4gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIMuhy8mFJGBAiW59fzWu2N4tfVfP8sEW8c1mTR1/VSQRN+b/hkhF2XGmh3aBQs41FCDQBpDT7JNES1Ww+HPv8uYkf7AaWCBvvlsvHfIjd2vRqWu4d1RW1r6q5O+nAsmkaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBQm12TZxXjCWmfRp95rEtAbY/HG1zAdBgNVHQ4EFgQU666CxP+hrFtR1M8kYQUAvmO9d4gwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQDdixo0gaX62du052V7hB4UTCe3W4dqQYbCsUdXUDNyJ+/lVEV+9kiVDGMuXEg+cMECMCyKYETcIB/P5ZvDTSkwwUh4Udlg7Wp18etKyr44zSW4l9DIBb7wx/eLB6VxxugOBw=="
        };
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
    public async Task TestAppleMissingX5c()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAppleX5cNotArray()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborTextString("boomerang"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAppleX5cCountNotOne()
    {
        var emptyX5c = new CborArray { new byte[0], new byte[0] };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", emptyX5c);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAppleX5cValueNotByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborTextString("x"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public async Task TestAppleX5cValueZeroLengthByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborArray { new byte[0] });
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public void TestAppleCertMissingExtension()
    {
        var invalidX5cStrings = validX5cStrings;
        var invalidCert = Convert.FromBase64String(invalidX5cStrings[0]);
        invalidCert[424] = 0x42;
        invalidX5cStrings[0] = Convert.ToBase64String(invalidCert);

        var trustPath = invalidX5cStrings
            .Select(x => new X509Certificate2(Convert.FromBase64String(x)))
            .ToArray();

        var x5c = new CborArray {
            trustPath[0].RawData,
            trustPath[1].RawData
        };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", x5c);
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Extension with OID 1.2.840.113635.100.8.2 not found on Apple attestation credCert", ex.Result.Message);
    }

    [Fact]
    public async Task TestAppleCertCorruptExtension()
    {
        var invalidX5cStrings = validX5cStrings;
        var invalidCert = Convert.FromBase64String(invalidX5cStrings[0]);
        invalidCert[429] = 0x03;
        invalidX5cStrings[0] = Convert.ToBase64String(invalidCert);

        var trustPath = invalidX5cStrings
            .Select(x => new X509Certificate2(Convert.FromBase64String(x)))
            .ToArray();

        var x5c = new CborArray {
            trustPath[0].RawData,
            trustPath[1].RawData
        };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", x5c);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Apple attestation extension has invalid data", ex.Message);
    }

    [Fact]
    public void TestAppleInvalidNonce()
    {
        var trustPath = validX5cStrings
            .Select(x => new X509Certificate2(Convert.FromBase64String(x)))
            .ToArray();

        var x5c = new CborArray { 
            trustPath[0].RawData,
            trustPath[1].RawData
        };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", x5c);
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Mismatch between nonce and credCert attestation extension in Apple attestation", ex.Result.Message);
    }

    [Fact]
    public async Task TestApplePublicKeyMismatch()
    {
        var cpkBytes = new byte[] { 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x79, 0xfe, 0x59, 0x08, 0xbb, 0x51, 0x29, 0xc8, 0x09, 0x38, 0xb7, 0x54, 0xc0, 0x4d, 0x2b, 0x34, 0x0e, 0xfa, 0x66, 0x15, 0xb9, 0x87, 0x69, 0x8b, 0xf5, 0x9d, 0xa4, 0xe5, 0x3e, 0xa3, 0xe6, 0xfe, 0x22, 0x58, 0x20, 0xfb, 0x03, 0xda, 0xa1, 0x27, 0x0d, 0x58, 0x04, 0xe8, 0xab, 0x61, 0xc1, 0x5a, 0xac, 0xa2, 0x43, 0x5c, 0x7d, 0xbf, 0x36, 0x9d, 0x71, 0xca, 0x15, 0xc5, 0x23, 0xb0, 0x00, 0x4a, 0x1b, 0x75, 0xb7 };
        _credentialPublicKey = new CredentialPublicKey(cpkBytes);

        var authData = new AuthenticatorData(_rpIdHash, _flags, _signCount, _acd, GetExtensions()).ToByteArray();
        _attestationObject.Set("authData", new CborByteString(authData));
        var clientData = new
        {
            type = "webauthn.create",
            challenge = _challenge,
            origin = "https://www.passwordless.dev",
        };
        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(clientData);

        var invalidX5cStrings = StackAllocSha256(authData, clientDataJson);

        var trustPath = invalidX5cStrings
            .Select(x => new X509Certificate2(Convert.FromBase64String(x)))
            .ToArray();

        var X5c = new CborArray {
            { trustPath[0].RawData },
            { trustPath[1].RawData }
        };

        ((CborMap)_attestationObject["attStmt"]).Set("x5c", X5c);

        var attestationResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = new byte[] { 0xf1, 0xd0 },
            RawId = new byte[] { 0xf1, 0xd0 },
            Response = new AuthenticatorAttestationRawResponse.ResponseData()
            {
                AttestationObject = _attestationObject.Encode(),
                ClientDataJson = clientDataJson,
            }
        };

        var origChallenge = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = _challenge,
            ErrorMessage = "",
            PubKeyCredParams = new List<PubKeyCredParam>()
            {
                PubKeyCredParam.ES256
            },
            Rp = new PublicKeyCredentialRpEntity("https://www.passwordless.dev", "6cc3c9e7967a.ngrok.io", ""),
            Status = "ok",
            User = new Fido2User
            {
                Name = "testuser",
                Id = "testuser"u8.ToArray(),
                DisplayName = "Test User",
            },
            Timeout = 60000,
        };

        IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var lib = new Fido2(new Fido2Configuration
        {
            ServerDomain = "6cc3c9e7967a.ngrok.io",
            ServerName = "6cc3c9e7967a.ngrok.io",
            Origins = new HashSet<string> { "https://www.passwordless.dev" },
        });

        var credentialMakeResult = await lib.MakeNewCredentialAsync(attestationResponse, origChallenge, callback);
    }

    private string[] StackAllocSha256(byte[] authData, byte[] clientDataJson)
    {
        var data = DataHelper.Concat(authData, SHA256.HashData(clientDataJson));
        Span<byte> dataHash = stackalloc byte[32];
        SHA256.HashData(data, dataHash);

        var invalidX5cStrings = validX5cStrings;
        var invalidCert = Convert.FromBase64String(invalidX5cStrings[0]);
        Buffer.BlockCopy(dataHash.ToArray(), 0, invalidCert, 433, 32);
        invalidCert[485] = 0xdb;
        invalidX5cStrings[0] = Convert.ToBase64String(invalidCert);

        return invalidX5cStrings;
    }
}
