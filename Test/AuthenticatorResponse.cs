using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

using NSec.Cryptography;

using Xunit;

namespace Test
{
    public class AuthenticatorResponse
    {
        [Theory]
        [InlineData("https://www.passwordless.dev", "https://www.passwordless.dev")]
        [InlineData("https://www.passwordless.dev:443", "https://www.passwordless.dev:443")]
        [InlineData("https://www.passwordless.dev", "https://www.passwordless.dev:443")]
        [InlineData("https://www.passwordless.dev:443", "https://www.passwordless.dev")]
        [InlineData("https://www.passwordless.dev:443/foo/bar.html","https://www.passwordless.dev:443/foo/bar.html")]
        [InlineData("https://www.passwordless.dev:443/foo/bar.html", "https://www.passwordless.dev:443/bar/foo.html")]
        [InlineData("https://www.passwordless.dev:443/foo/bar.html", "https://www.passwordless.dev/bar/foo.html")]
        [InlineData("https://www.passwordless.dev:443/foo/bar.html", "https://www.passwordless.dev")]
        [InlineData("ftp://www.passwordless.dev", "ftp://www.passwordless.dev")]
        [InlineData("ftp://www.passwordless.dev:8080", "ftp://www.passwordless.dev:8080")]
        [InlineData("http://127.0.0.1", "http://127.0.0.1")]
        [InlineData("http://localhost", "http://localhost")]
        [InlineData("https://127.0.0.1:80", "https://127.0.0.1:80")]
        [InlineData("http://localhost:80", "http://localhost:80")]
        [InlineData("http://127.0.0.1:443", "http://127.0.0.1:443")]
        [InlineData("http://localhost:443", "http://localhost:443")]
        [InlineData("android:apk-key-hash:Ea3dD4m7ccbwcw+a27/D547hfwYra2gKE4lIBbBjCTU", "android:apk-key-hash:Ea3dD4m7ccbwcw+a27/D547hfwYra2gKE4lIBbBjCTU")]
        [InlineData("lorem:ipsum:dolor", "lorem:ipsum:dolor")]
        [InlineData("lorem:/ipsum:4321", "lorem:/ipsum:4321")]
        [InlineData("lorem://ipsum:1234", "lorem://ipsum:1234")]
        [InlineData("lorem://ipsum:9876/sit", "lorem://ipsum:9876/sit")]
        [InlineData("foo://bar:321/path/", "foo://bar:321/path/")]
        [InlineData("foo://bar:321/path","foo://bar:321/path")]
        [InlineData("http://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]")]
        [InlineData("http://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]:80")]
        [InlineData("https://[0:0:0:0:0:0:0:1]", "https://[0:0:0:0:0:0:0:1]")]
        [InlineData("https://[0:0:0:0:0:0:0:1]", "https://[0:0:0:0:0:0:0:1]:443")]
        public async Task TestAuthenticatorOrigins(string origin, string expectedOrigin)
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            challenge = Encoding.UTF8.GetBytes(Base64Url.Encode(challenge));
            var rp = origin;
            var acd = new AttestedCredentialData(("00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-40-FE-6A-32-63-BE-37-D1-01-B1-2E-57-CA-96-6C-00-22-93-E4-19-C8-CD-01-06-23-0B-C6-92-E8-CC-77-12-21-F1-DB-11-5D-41-0F-82-6B-DB-98-AC-64-2E-B1-AE-B5-A8-03-D1-DB-C1-47-EF-37-1C-FD-B1-CE-B0-48-CB-2C-A5-01-02-03-26-20-01-21-58-20-A6-D1-09-38-5A-C7-8E-5B-F0-3D-1C-2E-08-74-BE-6D-BB-A4-0B-4F-2A-5F-2F-11-82-45-65-65-53-4F-67-28-22-58-20-43-E1-08-2A-F3-13-5B-40-60-93-79-AC-47-42-58-AA-B3-97-B8-86-1D-E4-41-B4-4E-83-08-5D-1C-6B-E0-D0").Split('-').Select(c => Convert.ToByte(c, 16)).ToArray());
            var authData = new AuthenticatorData(
                SHA256.HashData(Encoding.UTF8.GetBytes(origin)),
                AuthenticatorFlags.UP | AuthenticatorFlags.AT,
                0,
                acd
            ).ToByteArray();

            byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new 
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp
            });
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "none" },
                        { "attStmt", new CborMap() },
                        { "authData", authData }
                    }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { expectedOrigin },
            });

            var result = await lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback);
        }


        [Theory]
        [InlineData("https://www.passwordless.dev", "http://www.passwordless.dev")]
        [InlineData("https://www.passwordless.dev:443", "http://www.passwordless.dev:443")]
        [InlineData("https://www.passwordless.dev", "http://www.passwordless.dev:443")]
        [InlineData("https://www.passwordless.dev:443", "http://www.passwordless.dev")]
        [InlineData("https://www.passwordless.dev:443/foo/bar.html", "http://www.passwordless.dev:443/foo/bar.html")]
        [InlineData("https://www.passwordless.dev:443/foo/bar.html", "http://www.passwordless.dev:443/bar/foo.html")]
        [InlineData("https://www.passwordless.dev:443/foo/bar.html", "http://www.passwordless.dev/bar/foo.html")]
        [InlineData("https://www.passwordless.dev:443/foo/bar.html", "http://www.passwordless.dev")]
        [InlineData("ftp://www.passwordless.dev", "ftp://www.passwordless.dev:80")]
        [InlineData("ftp://www.passwordless.dev:8080", "ftp://www.passwordless.dev:8081")]
        [InlineData("https://127.0.0.1", "http://127.0.0.1")]
        [InlineData("https://localhost", "http://localhost")]
        [InlineData("https://127.0.0.1:80", "https://127.0.0.1:81")]
        [InlineData("http://localhost:80", "http://localhost:82")]
        [InlineData("http://127.0.0.1:443", "http://127.0.0.1:444")]
        [InlineData("http://localhost:443", "http://localhost:444")]
        [InlineData("android:apk-key-hash:Ea3dD4m7ccbwcw+a27/D547hfwYra2gKE4lIBbBjCTU", "android:apk-key-hash:Ae3dD4m7ccbwcw+a27/D547hfwYra2gKE4lIBbBjCTU")]
        [InlineData("lorem:ipsum:dolor", "lorem:dolor:ipsum")]
        [InlineData("lorem:/ipsum:4321", "lorem:/ipsum:4322")]
        [InlineData("lorem://ipsum:1234", "lorem://ipsum:1235")]
        [InlineData("lorem://ipsum:9876/sit", "lorem://ipsum:9877/sit")]
        [InlineData("foo://bar:321/path/", "foo://bar:322/path/")]
        [InlineData("foo://bar:321/path", "foo://bar:322/path")]
        [InlineData("https://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]")]
        [InlineData("https://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]:80")]
        [InlineData("http://[0:0:0:0:0:0:0:1]", "https://[0:0:0:0:0:0:0:1]")]
        [InlineData("http://[0:0:0:0:0:0:0:1]", "https://[0:0:0:0:0:0:0:1]:443")]
        public void TestAuthenticatorOriginsFail(string origin, string expectedOrigin)
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            challenge = Encoding.UTF8.GetBytes(Base64Url.Encode(challenge));
            var rp = origin;
            var acd = new AttestedCredentialData(("00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-40-FE-6A-32-63-BE-37-D1-01-B1-2E-57-CA-96-6C-00-22-93-E4-19-C8-CD-01-06-23-0B-C6-92-E8-CC-77-12-21-F1-DB-11-5D-41-0F-82-6B-DB-98-AC-64-2E-B1-AE-B5-A8-03-D1-DB-C1-47-EF-37-1C-FD-B1-CE-B0-48-CB-2C-A5-01-02-03-26-20-01-21-58-20-A6-D1-09-38-5A-C7-8E-5B-F0-3D-1C-2E-08-74-BE-6D-BB-A4-0B-4F-2A-5F-2F-11-82-45-65-65-53-4F-67-28-22-58-20-43-E1-08-2A-F3-13-5B-40-60-93-79-AC-47-42-58-AA-B3-97-B8-86-1D-E4-41-B4-4E-83-08-5D-1C-6B-E0-D0").Split('-').Select(c => Convert.ToByte(c, 16)).ToArray());
            var authData = new AuthenticatorData(
                SHA256.HashData(Encoding.UTF8.GetBytes(origin)),
                AuthenticatorFlags.UP | AuthenticatorFlags.AT,
                0,
                acd
            ).ToByteArray();
            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "none" },
                        { "attStmt", new CborMap() },
                        { "authData", authData }
                    }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { expectedOrigin },
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.StartsWith("Fully qualified origin", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationRawResponse()
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new
            {
                Type = "webauthn.create",
                Challenge = challenge,
                Origin = "https://www.passwordless.dev",
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap().Encode(),
                    ClientDataJson = clientDataJson
                },
                Extensions = new AuthenticationExtensionsClientOutputs()
                {
                    AppID = true,
                    AuthenticatorSelectionCriteria = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                    {
                        new ulong[]
                        {
                            4 // USER_VERIFY_PASSCODE_INTERNAL
                        },
                    },
                }
            };
            Assert.Equal(PublicKeyCredentialType.PublicKey, rawResponse.Type);
            Assert.True(rawResponse.Id.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
            Assert.True(rawResponse.RawId.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
            Assert.True(rawResponse.Response.AttestationObject.SequenceEqual(new byte[] { 0xa0 }));
            Assert.True(rawResponse.Response.ClientDataJson.SequenceEqual(clientDataJson));
            Assert.True(rawResponse.Extensions.AppID);
            Assert.True(rawResponse.Extensions.AuthenticatorSelectionCriteria);
            Assert.Equal(rawResponse.Extensions.Extensions, new string[] { "foo", "bar" });
            Assert.Equal("test", rawResponse.Extensions.Example);
            Assert.Equal((ulong)4, rawResponse.Extensions.UserVerificationMethod[0][0]);
        }

        [Fact]
        public void TestAuthenticatorAttestationRawResponseNull()
        {
            var ex = Assert.Throws<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(null));
            Assert.Equal("Expected rawResponse, got null", ex.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseNull()
        {
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = null,
            };
            var ex = Assert.Throws<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));
            Assert.Equal("Expected rawResponse, got null", ex.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        public void TestAuthenticatorAttestationReponseAttestationObjectNull(byte[] value)
        {
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = value,
                }
            };
            var ex = Assert.Throws<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));
            Assert.Equal("Missing AttestationObject", ex.Message);
        }

        [Theory]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f })]
        public void TestAuthenticatorAttestationObjectBadCBOR(byte[] value)
        {
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = value,
                }
            };

            var ex = Assert.Throws<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));
            Assert.Equal("AttestationObject invalid CBOR", ex.Message);

            var innerEx = (CborContentException)ex.InnerException;

            Assert.Equal("Declared definite length of CBOR data item exceeds available buffer size.", innerEx.Message);
        }

        [Theory]
        [InlineData(new byte[] { 0xa1, 0x63, 0x66, 0x6d, 0x74, 0xf6 })] // "fmt", null
        [InlineData(new byte[] { 0xa1, 0x63, 0x66, 0x6d, 0x74, 0x18, 0x2a })] // "fmt", 42
        [InlineData(new byte[] { 0xa1, 0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0xf6 })] // "attStmt", null
        [InlineData(new byte[] { 0xa1, 0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74 })] // "attStmt", "attStmt"
        [InlineData(new byte[] { 0xa1, 0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0xf6 })] // "authData", null
        [InlineData(new byte[] { 0xa1, 0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61 })] // "authData", "authData"
        public void TestAuthenticatorAttestationObjectMalformed(byte[] value)
        {
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = value,
                }
            };

            var ex = Assert.Throws<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));
            Assert.Equal("Malformed AttestationObject", ex.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseInvalidType()
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            var rp = "https://www.passwordless.dev";
            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new 
            {
                Type = "webauthn.get",
                Challenge = challenge,
                Origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "testing" },
                        { "attStmt", new CborMap() },
                        { "authData", new byte[0] }
                    }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("AttestationResponse is not type webauthn.create", ex.Result.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        public void TestAuthenticatorAttestationResponseInvalidRawId(byte[] value)
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            challenge = Encoding.UTF8.GetBytes(Base64Url.Encode(challenge));
            var rp = "https://www.passwordless.dev";
            byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = value,
                RawId = value,
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "testing" },
                        { "attStmt", new CborMap() },
                        { "authData", Array.Empty<byte>() }
                    }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("AttestationResponse is missing Id", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseInvalidRawType()
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            challenge = Encoding.UTF8.GetBytes(Base64Url.Encode(challenge));
            var rp = "https://www.passwordless.dev";
            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = null,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "testing" },
                        { "attStmt", new CborMap() },
                        { "authData", Array.Empty<byte>() }
                    }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("AttestationResponse is missing type with value 'public-key'", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseRpidMismatch()
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            challenge = Encoding.UTF8.GetBytes(Base64Url.Encode(challenge));
            var rp = "https://www.passwordless.dev";
            var authData = new AuthenticatorData(
                SHA256.HashData(Encoding.UTF8.GetBytes("passwordless.dev")),
                AuthenticatorFlags.UV,
                0,
                null
            ).ToByteArray();

            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "testing" },
                        { "attStmt", new CborMap() },
                        { "authData", authData }
                    }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("Hash mismatch RPID", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseNotUserPresent()
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            challenge = Encoding.UTF8.GetBytes(Base64Url.Encode(challenge));
            var rp = "https://www.passwordless.dev";
            var authData = new AuthenticatorData(
                SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
                AuthenticatorFlags.UV,
                0,
                null
            ).ToByteArray();

            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new 
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "testing" },
                        { "attStmt", new CborMap() },
                        { "authData", authData }
                    }.Encode(),

                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("User Present flag not set in authenticator data", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseNoAttestedCredentialData()
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            challenge = Encoding.UTF8.GetBytes(Base64Url.Encode(challenge));
            var rp = "https://www.passwordless.dev";
            var authData = new AuthenticatorData(
                SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
                AuthenticatorFlags.UP | AuthenticatorFlags.UV,
                0,
                null
            ).ToByteArray();

            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "testing" },
                        { "attStmt", new CborMap() },
                        { "authData", authData }
                    }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("Attestation flag not set on attestation data", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseUnknownAttestationType()
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            challenge = Encoding.UTF8.GetBytes(Base64Url.Encode(challenge));
            var rp = "https://www.passwordless.dev";
            var acd = new AttestedCredentialData(("00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-40-FE-6A-32-63-BE-37-D1-01-B1-2E-57-CA-96-6C-00-22-93-E4-19-C8-CD-01-06-23-0B-C6-92-E8-CC-77-12-21-F1-DB-11-5D-41-0F-82-6B-DB-98-AC-64-2E-B1-AE-B5-A8-03-D1-DB-C1-47-EF-37-1C-FD-B1-CE-B0-48-CB-2C-A5-01-02-03-26-20-01-21-58-20-A6-D1-09-38-5A-C7-8E-5B-F0-3D-1C-2E-08-74-BE-6D-BB-A4-0B-4F-2A-5F-2F-11-82-45-65-65-53-4F-67-28-22-58-20-43-E1-08-2A-F3-13-5B-40-60-93-79-AC-47-42-58-AA-B3-97-B8-86-1D-E4-41-B4-4E-83-08-5D-1C-6B-E0-D0").Split('-').Select(c => Convert.ToByte(c, 16)).ToArray());
            var authData = new AuthenticatorData(
                SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
                AuthenticatorFlags.AT | AuthenticatorFlags.UP | AuthenticatorFlags.UV,
                0,
                acd
            ).ToByteArray();

            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });
                   
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "testing" },
                        { "attStmt", new CborMap() },
                        { "authData", authData }
                    }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("Missing or unknown attestation type", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseNotUniqueCredId()
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            challenge = Encoding.UTF8.GetBytes(Base64Url.Encode(challenge));
            var rp = "https://www.passwordless.dev";
            var acd = new AttestedCredentialData(("00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-40-FE-6A-32-63-BE-37-D1-01-B1-2E-57-CA-96-6C-00-22-93-E4-19-C8-CD-01-06-23-0B-C6-92-E8-CC-77-12-21-F1-DB-11-5D-41-0F-82-6B-DB-98-AC-64-2E-B1-AE-B5-A8-03-D1-DB-C1-47-EF-37-1C-FD-B1-CE-B0-48-CB-2C-A5-01-02-03-26-20-01-21-58-20-A6-D1-09-38-5A-C7-8E-5B-F0-3D-1C-2E-08-74-BE-6D-BB-A4-0B-4F-2A-5F-2F-11-82-45-65-65-53-4F-67-28-22-58-20-43-E1-08-2A-F3-13-5B-40-60-93-79-AC-47-42-58-AA-B3-97-B8-86-1D-E4-41-B4-4E-83-08-5D-1C-6B-E0-D0").Split('-').Select(c => Convert.ToByte(c, 16)).ToArray());
            var authData = new AuthenticatorData(
                SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
                AuthenticatorFlags.AT | AuthenticatorFlags.UP | AuthenticatorFlags.UV,
                0,
                acd
            ).ToByteArray();
            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "none" },
                        { "attStmt", new CborMap() },
                        { "authData", authData }
                    }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(false);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("CredentialId is not unique to this user", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseUVRequired()
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            challenge = Encoding.UTF8.GetBytes(Base64Url.Encode(challenge));
            var rp = "https://www.passwordless.dev";
            var acd = new AttestedCredentialData(("00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-40-FE-6A-32-63-BE-37-D1-01-B1-2E-57-CA-96-6C-00-22-93-E4-19-C8-CD-01-06-23-0B-C6-92-E8-CC-77-12-21-F1-DB-11-5D-41-0F-82-6B-DB-98-AC-64-2E-B1-AE-B5-A8-03-D1-DB-C1-47-EF-37-1C-FD-B1-CE-B0-48-CB-2C-A5-01-02-03-26-20-01-21-58-20-A6-D1-09-38-5A-C7-8E-5B-F0-3D-1C-2E-08-74-BE-6D-BB-A4-0B-4F-2A-5F-2F-11-82-45-65-65-53-4F-67-28-22-58-20-43-E1-08-2A-F3-13-5B-40-60-93-79-AC-47-42-58-AA-B3-97-B8-86-1D-E4-41-B4-4E-83-08-5D-1C-6B-E0-D0").Split('-').Select(c => Convert.ToByte(c, 16)).ToArray());
            var authData = new AuthenticatorData(
                SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
                AuthenticatorFlags.AT | AuthenticatorFlags.UP,
                0,
                acd
            ).ToByteArray();
            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                        { "fmt", "none" },
                        { "attStmt", new CborMap() },
                        { "authData", authData }
                    }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new PublicKeyCredentialCreationOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelectionCriteria = new AuthenticatorSelectionCriteria
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Required,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PublicKeyCredentialParameters = new List<PublicKeyCredentialParameters>()
                {
                    new PublicKeyCredentialParameters(COSE.Algorithm.ES256)
                },
                Rp = new PublicKeyCredentialRpEntity(rp),
                Status = "ok",
                User = new Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("User Verified flag not set in authenticator data and user verification was required", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAssertionRawResponse()
        {
            var challenge = RandomNumberGenerator.GetBytes(128);
            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new
            {
                Type = "webauthn.get",
                Challenge = challenge,
                Origin = "https://www.passwordless.dev",
            });

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new byte[] { 0xf1, 0xd0 },
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs()
                {
                    AppID = true,
                    AuthenticatorSelectionCriteria = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                    {
                        new ulong[]
                        {
                            4 // USER_VERIFY_PASSCODE_INTERNAL
                        },
                    },
                }
            };
            Assert.Equal(PublicKeyCredentialType.PublicKey, assertionResponse.Type);
            Assert.True(assertionResponse.Id.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
            Assert.True(assertionResponse.RawId.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
            Assert.True(assertionResponse.Response.AuthenticatorData.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
            Assert.True(assertionResponse.Response.Signature.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
            Assert.True(assertionResponse.Response.ClientDataJson.SequenceEqual(clientDataJson));
            Assert.True(assertionResponse.Response.UserHandle.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
            Assert.True(assertionResponse.Extensions.AppID);
            Assert.True(assertionResponse.Extensions.AuthenticatorSelectionCriteria);
            Assert.Equal(assertionResponse.Extensions.Extensions, new string[] { "foo", "bar" });
            Assert.Equal("test", assertionResponse.Extensions.Example);
            Assert.Equal((ulong)4, assertionResponse.Extensions.UserVerificationMethod[0][0]);
        }
    }
}
