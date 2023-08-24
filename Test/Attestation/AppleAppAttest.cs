using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Test.Attestation;

public class AppleAppAttest : Fido2Tests.Attestation
{
    public string[] validX5cStrings;
    public AppleAppAttest()
    {
        var b64 = "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";
        var cbor = Convert.FromBase64String(b64);
        _attestationObject = (CborMap)CborObject.Decode(cbor);
        _aaguid = new("61707061-7474-6573-7464-6576656c6f70");

        //_attestationObject = new ParsedAttestationObject
        //(
        //    fmt: (string)json["fmt"],
        //    attStmt: (CborMap)json["attStmt"],
        //    authData: (byte[])json["authData"]
        //);

        validX5cStrings = new[] {
            "MIICRDCCAcmgAwIBAgIGAXUCfWGDMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAxMDA3MDk0NjEyWhcNMjAxMDA4MDk1NjEyWjCBkTFJMEcGA1UEAwxANjEyNzZmYzAyZDNmZThkMTZiMzNiNTU0OWQ4MTkyMzZjODE3NDZhODNmMmU5NGE2ZTRiZWUxYzcwZjgxYjViYzEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR5/lkIu1EpyAk4t1TATSs0DvpmFbmHaYv1naTlPqPm/vsD2qEnDVgE6KthwVqsokNcfb82nXHKFcUjsABKG3W3o1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIJxgAhVAs+GYNN/jfsYkRcieGylPeSzka5QTwyMO84aBMAoGCCqGSM49BAMCA2kAMGYCMQDaHBjrI75xAF7SXzyF5zSQB/Lg9PjTdyye+w7stiqy84K6lmo8d3fIptYjLQx81bsCMQCvC8MSN+aewiaU0bMsdxRbdDerCJJj3xJb3KZwloevJ3daCmCcrZrAPYfLp2kDOsg=",
            "MIICNDCCAbqgAwIBAgIQViVTlcen+0Dr4ijYJghTtjAKBggqhkjOPQQDAzBLMR8wHQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MzgwMVoXDTMwMDMxMzAwMDAwMFowSDEcMBoGA1UEAwwTQXBwbGUgV2ViQXV0aG4gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIMuhy8mFJGBAiW59fzWu2N4tfVfP8sEW8c1mTR1/VSQRN+b/hkhF2XGmh3aBQs41FCDQBpDT7JNES1Ww+HPv8uYkf7AaWCBvvlsvHfIjd2vRqWu4d1RW1r6q5O+nAsmkaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBQm12TZxXjCWmfRp95rEtAbY/HG1zAdBgNVHQ4EFgQU666CxP+hrFtR1M8kYQUAvmO9d4gwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQDdixo0gaX62du052V7hB4UTCe3W4dqQYbCsUdXUDNyJ+/lVEV+9kiVDGMuXEg+cMECMCyKYETcIB/P5ZvDTSkwwUh4Udlg7Wp18etKyr44zSW4l9DIBb7wx/eLB6VxxugOBw=="
        };
        //_attestationObject = new CborMap { { "fmt", "apple-appattest" } };
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
    public void TestAppleAppAttestMissingX5c()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", CborNull.Instance);
        var verifier = new Fido2NetLib.AppleAppAttest();
        var ex = Assert.Throws<Fido2VerificationException>(
        () => { (AttestationType attType, X509Certificate[] trustPath) = verifier.Verify(attStmt, _authData, _clientDataJson); });

        Assert.Equal("Malformed x5c in Apple AppAttest attestation", ex.Message);
    }

    [Fact]
    public void TestAppleAppAttestX5cNotArray()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborTextString("boomerang"));
        var verifier = new Fido2NetLib.AppleAppAttest();
        var ex = Assert.Throws<Fido2VerificationException>(
        () => { (AttestationType attType, X509Certificate[] trustPath) = verifier.Verify(attStmt, _authData, _clientDataJson); });

        Assert.Equal("Malformed x5c in Apple AppAttest attestation", ex.Message);
    }

    [Fact]
    public void TestAppleAppAttestX5cCountNotTwo()
    {
        var emptyX5c = new CborArray { new byte[0] };
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", emptyX5c);
        var verifier = new Fido2NetLib.AppleAppAttest();
        var ex = Assert.Throws<Fido2VerificationException>(
        () => { (AttestationType attType, X509Certificate[] trustPath) = verifier.Verify(attStmt, _authData, _clientDataJson); });

        Assert.Equal("Malformed x5c in Apple AppAttest attestation", ex.Message);
    }

    [Fact]
    public void TestAppleAppAttestX5cValueNotByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborTextString("x"));
        var verifier = new Fido2NetLib.AppleAppAttest();
        var ex = Assert.Throws<Fido2VerificationException>(
        () => { (AttestationType attType, X509Certificate[] trustPath) = verifier.Verify(attStmt, _authData, _clientDataJson); });

        Assert.Equal("Malformed x5c in Apple AppAttest attestation", ex.Message);
    }

    [Fact]
    public void TestAppleAppAttestX5cValueZeroLengthByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("x5c", new CborArray { new byte[0] });
        var verifier = new Fido2NetLib.AppleAppAttest();
        var ex = Assert.Throws<Fido2VerificationException>(
        () => { (AttestationType attType, X509Certificate[] trustPath) = verifier.Verify(attStmt, _authData, _clientDataJson); });

        Assert.Equal("Malformed x5c in Apple AppAttest attestation", ex.Message);
    }
}
