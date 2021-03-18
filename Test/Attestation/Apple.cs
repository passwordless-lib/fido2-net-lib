﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using fido2_net_lib.Test;
using Fido2NetLib;
using Fido2NetLib.Objects;
using PeterO.Cbor;
using Xunit;
using System.Threading.Tasks;
using System.Text;

namespace Test.Attestation
{
    public class Apple : Fido2Tests.Attestation
    {
        public string[] validX5cStrings;
        public Apple()
        {
            validX5cStrings = new[] {
                "MIICRDCCAcmgAwIBAgIGAXUCfWGDMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAxMDA3MDk0NjEyWhcNMjAxMDA4MDk1NjEyWjCBkTFJMEcGA1UEAwxANjEyNzZmYzAyZDNmZThkMTZiMzNiNTU0OWQ4MTkyMzZjODE3NDZhODNmMmU5NGE2ZTRiZWUxYzcwZjgxYjViYzEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR5/lkIu1EpyAk4t1TATSs0DvpmFbmHaYv1naTlPqPm/vsD2qEnDVgE6KthwVqsokNcfb82nXHKFcUjsABKG3W3o1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIJxgAhVAs+GYNN/jfsYkRcieGylPeSzka5QTwyMO84aBMAoGCCqGSM49BAMCA2kAMGYCMQDaHBjrI75xAF7SXzyF5zSQB/Lg9PjTdyye+w7stiqy84K6lmo8d3fIptYjLQx81bsCMQCvC8MSN+aewiaU0bMsdxRbdDerCJJj3xJb3KZwloevJ3daCmCcrZrAPYfLp2kDOsg=",
                "MIICNDCCAbqgAwIBAgIQViVTlcen+0Dr4ijYJghTtjAKBggqhkjOPQQDAzBLMR8wHQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MzgwMVoXDTMwMDMxMzAwMDAwMFowSDEcMBoGA1UEAwwTQXBwbGUgV2ViQXV0aG4gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIMuhy8mFJGBAiW59fzWu2N4tfVfP8sEW8c1mTR1/VSQRN+b/hkhF2XGmh3aBQs41FCDQBpDT7JNES1Ww+HPv8uYkf7AaWCBvvlsvHfIjd2vRqWu4d1RW1r6q5O+nAsmkaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBQm12TZxXjCWmfRp95rEtAbY/HG1zAdBgNVHQ4EFgQU666CxP+hrFtR1M8kYQUAvmO9d4gwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQDdixo0gaX62du052V7hB4UTCe3W4dqQYbCsUdXUDNyJ+/lVEV+9kiVDGMuXEg+cMECMCyKYETcIB/P5ZvDTSkwwUh4Udlg7Wp18etKyr44zSW4l9DIBb7wx/eLB6VxxugOBw=="
            };
            _attestationObject = CBORObject.NewMap().Add("fmt", "apple");
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.apple.com, OU=Apple Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                var curve = (COSE.EllipticCurve)param[2];
                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                    }

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
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(root.RawData));

                    _attestationObject.Add("attStmt", CBORObject.NewMap().Add("x5c", X5c));
                }
            }
        }
        [Fact]
        public void TestAppleMissingX5c()
        {
            _attestationObject["attStmt"].Set("x5c", null);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in Apple attestation", ex.Result.Message);
        }
        [Fact]
        public void TestAppleX5cNotArray()
        {
            _attestationObject["attStmt"].Set("x5c", "boomerang");
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in Apple attestation", ex.Result.Message);
        }
        [Fact]
        public void TestAppleX5cCountNotOne()
        {
            _attestationObject["attStmt"]
                .Set("x5c", CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0])).Add(CBORObject.FromObject(new byte[0])));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in Apple attestation", ex.Result.Message);
        }
        [Fact]
        public void TestAppleX5cValueNotByteString()
        {
            _attestationObject["attStmt"].Set("x5c", "x".ToArray());
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in Apple attestation", ex.Result.Message);
        }
        [Fact]
        public void TestAppleX5cValueZeroLengthByteString()
        {
            _attestationObject["attStmt"].Set("x5c", CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0])));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Malformed x5c in Apple attestation", ex.Result.Message);
        }

        [Fact]
        public void TestAppleChainValidationFail()
        {
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid certificate chain in Apple attestation", ex.Result.Message);
        }

        [Fact(Skip = "Cert chain issues")]
        public void TestAppleInvalidNonce()
        {
            var trustPath = validX5cStrings
                .Select(x => new X509Certificate2(Convert.FromBase64String(x)))
                .ToArray();

            var X5c = CBORObject.NewArray()
                .Add(CBORObject.FromObject(trustPath[0].RawData))
                .Add(CBORObject.FromObject(trustPath[1].RawData));

            _attestationObject["attStmt"].Set("x5c", X5c);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Mismatch between nonce and credCert attestation extension in Apple attestation", ex.Result.Message);
        }

        [Fact]
        public void TestApplePublicKeyMismatch()
        {
            var cpkBytes = new byte[] { 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x79, 0xfe, 0x59, 0x08, 0xbb, 0x51, 0x29, 0xc8, 0x09, 0x38, 0xb7, 0x54, 0xc0, 0x4d, 0x2b, 0x34, 0x0e, 0xfa, 0x66, 0x15, 0xb9, 0x87, 0x69, 0x8b, 0xf5, 0x9d, 0xa4, 0xe5, 0x3e, 0xa3, 0xe6, 0xfe, 0x22, 0x58, 0x20, 0xfb, 0x03, 0xda, 0xa1, 0x27, 0x0d, 0x58, 0x04, 0xe8, 0xab, 0x61, 0xc1, 0x5a, 0xac, 0xa2, 0x43, 0x5c, 0x7d, 0xbf, 0x36, 0x9d, 0x71, 0xca, 0x15, 0xc5, 0x23, 0xb0, 0x00, 0x4a, 0x1b, 0x75, 0xb7 };
            _credentialPublicKey = new CredentialPublicKey(cpkBytes);
            var trustPath = validX5cStrings
                .Select(x => new X509Certificate2(Convert.FromBase64String(x)))
                .ToArray();

            var X5c = CBORObject.NewArray()
                .Add(CBORObject.FromObject(trustPath[0].RawData))
                .Add(CBORObject.FromObject(trustPath[1].RawData));

            _attestationObject["attStmt"].Set("x5c", X5c);

            var authData = new AuthenticatorData(_rpIdHash, _flags, _signCount, _acd, _exts).ToByteArray();
            _attestationObject.Set("authData", authData);
            var clientData = new
            {
                Type = "webauthn.create",
                Challenge = _challenge,
                Origin = "6cc3c9e7967a.ngrok.io",
            };
            var clientDataJson = Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(clientData));

            var attestationResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = _attestationObject.EncodeToBytes(),
                    ClientDataJson = clientDataJson,
                }
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Required,
                },
                Challenge = _challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam
                    {
                        Alg = COSE.Algorithm.ES256,
                        Type = PublicKeyCredentialType.PublicKey,
                    }
                },
                Rp = new PublicKeyCredentialRpEntity("6cc3c9e7967a.ngrok.io", "6cc3c9e7967a.ngrok.io", ""),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args) =>
            {
                return Task.FromResult(true);
            };

            var lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = "6cc3c9e7967a.ngrok.io",
                ServerName = "6cc3c9e7967a.ngrok.io",
                Origin = "6cc3c9e7967a.ngrok.io",
            });

            var credentialMakeResult = lib.MakeNewCredentialAsync(attestationResponse, origChallenge, callback);
        }
    }
}
