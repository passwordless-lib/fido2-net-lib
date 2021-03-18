using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Newtonsoft.Json;
using NSec.Cryptography;
using PeterO.Cbor;
using Xunit;

namespace Test
{
    public class AuthenticatorResponse
    {
        [Fact]
        public void TestAuthenticatorAttestationRawResponse()
        {
            var challenge = RandomGenerator.Default.GenerateBytes(128);
            var clientDataJson = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject
                    (
                        new
                        {
                            Type = "webauthn.create",
                            Challenge = challenge,
                            Origin = "fido2.azurewebsites.net",
                        }
                    )
                );
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = CBORObject.NewMap().EncodeToBytes(),
                    ClientDataJson = clientDataJson
                },
                Extensions = new AuthenticationExtensionsClientOutputs()
                {
                    AppID = true,
                    AuthenticatorSelection = true,
                    BiometricAuthenticatorPerformanceBounds = true,
                    GenericTransactionAuthorization = new byte[] { 0xf1, 0xd0 },
                    SimpleTransactionAuthorization = "test",
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    Location = new GeoCoordinatePortable.GeoCoordinate(42.523714, -71.040860),
                    UserVerificationIndex = new byte[] { 0xf1, 0xd0 },
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
            Assert.True(rawResponse.Extensions.AuthenticatorSelection);
            Assert.True(rawResponse.Extensions.BiometricAuthenticatorPerformanceBounds);
            Assert.True(rawResponse.Extensions.GenericTransactionAuthorization.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
            Assert.Equal("test", rawResponse.Extensions.SimpleTransactionAuthorization);
            Assert.Equal(rawResponse.Extensions.Extensions, new string[] { "foo", "bar" });
            Assert.Equal("test", rawResponse.Extensions.Example);
            Assert.Equal(42.523714, rawResponse.Extensions.Location.Latitude);
            Assert.Equal(-71.040860, rawResponse.Extensions.Location.Longitude);
            Assert.True(rawResponse.Extensions.UserVerificationIndex.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
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
            var challenge = RandomGenerator.Default.GenerateBytes(128);
            var rp = "fido2.azurewebsites.net";
            var clientDataJson = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject
                    (
                        new
                        {
                            Type = "webauthn.get",
                            Challenge = challenge,
                            Origin = rp,
                        }
                    )
                );
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = CBORObject.NewMap().Add("fmt", "testing").Add("attStmt", CBORObject.NewMap()).Add("authData", new byte[0]).EncodeToBytes(),
                    ClientDataJson = clientDataJson
                },
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
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam
                    {
                        Alg = COSE.Algorithm.ES256,
                        Type = PublicKeyCredentialType.PublicKey,
                    }
                },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("AttestationResponse is not type webauthn.create", ex.Result.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        public void TestAuthenticatorAttestationResponseInvalidRawId(byte[] value)
        {
            var challenge = RandomGenerator.Default.GenerateBytes(128);
            var rp = "fido2.azurewebsites.net";
            var clientDataJson = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject
                    (
                        new
                        {
                            Type = "webauthn.create",
                            Challenge = challenge,
                            Origin = rp,
                        }
                    )
                );
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = value,
                RawId = value,
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = CBORObject.NewMap().Add("fmt", "testing").Add("attStmt", CBORObject.NewMap()).Add("authData", new byte[0]).EncodeToBytes(),
                    ClientDataJson = clientDataJson
                },
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
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam
                    {
                        Alg = COSE.Algorithm.ES256,
                        Type = PublicKeyCredentialType.PublicKey,
                    }
                },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("AttestationResponse is missing Id", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseInvalidRawType()
        {
            var challenge = RandomGenerator.Default.GenerateBytes(128);
            var rp = "fido2.azurewebsites.net";
            var clientDataJson = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject
                    (
                        new
                        {
                            Type = "webauthn.create",
                            Challenge = challenge,
                            Origin = rp,
                        }
                    )
                );
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = null,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = CBORObject.NewMap().Add("fmt", "testing").Add("attStmt", CBORObject.NewMap()).Add("authData", new byte[0]).EncodeToBytes(),
                    ClientDataJson = clientDataJson
                },
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
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam
                    {
                        Alg = COSE.Algorithm.ES256,
                        Type = PublicKeyCredentialType.PublicKey,
                    }
                },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("AttestationResponse is missing type with value 'public-key'", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseRpidMismatch()
        {
            var challenge = RandomGenerator.Default.GenerateBytes(128);
            var rp = "fido2.azurewebsites.net";
            var authData = new AuthenticatorData(
                SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("passwordless.dev")),
                AuthenticatorFlags.UV,
                0,
                null,
                null
                ).ToByteArray();
            var clientDataJson = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject
                    (
                        new
                        {
                            Type = "webauthn.create",
                            Challenge = challenge,
                            Origin = rp,
                        }
                    )
                );
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = CBORObject.NewMap().Add("fmt", "testing").Add("attStmt", CBORObject.NewMap()).Add("authData", authData).EncodeToBytes(),
                    ClientDataJson = clientDataJson
                },
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
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam
                    {
                        Alg = COSE.Algorithm.ES256,
                        Type = PublicKeyCredentialType.PublicKey,
                    }
                },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("Hash mismatch RPID", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseNotUserPresent()
        {
            var challenge = RandomGenerator.Default.GenerateBytes(128);
            var rp = "fido2.azurewebsites.net";
            var authData = new AuthenticatorData(
                SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(rp)),
                AuthenticatorFlags.UV,
                0,
                null,
                null
                ).ToByteArray();
            var clientDataJson = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject
                    (
                        new
                        {
                            Type = "webauthn.create",
                            Challenge = challenge,
                            Origin = rp,
                        }
                    )
                );
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = CBORObject.NewMap().Add("fmt", "testing").Add("attStmt", CBORObject.NewMap()).Add("authData", authData).EncodeToBytes(),
                    ClientDataJson = clientDataJson
                },
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
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam
                    {
                        Alg = COSE.Algorithm.ES256,
                        Type = PublicKeyCredentialType.PublicKey,
                    }
                },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("User Present flag not set in authenticator data", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseNoAttestedCredentialData()
        {
            var challenge = RandomGenerator.Default.GenerateBytes(128);
            var rp = "fido2.azurewebsites.net";
            var authData = new AuthenticatorData(
                SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(rp)),
                AuthenticatorFlags.UP | AuthenticatorFlags.UV,
                0,
                null,
                null
                ).ToByteArray();
            var clientDataJson = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject
                    (
                        new
                        {
                            Type = "webauthn.create",
                            Challenge = challenge,
                            Origin = rp,
                        }
                    )
                );
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = CBORObject.NewMap().Add("fmt", "testing").Add("attStmt", CBORObject.NewMap()).Add("authData", authData).EncodeToBytes(),
                    ClientDataJson = clientDataJson
                },
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
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam
                    {
                        Alg = COSE.Algorithm.ES256,
                        Type = PublicKeyCredentialType.PublicKey,
                    }
                },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("Attestation flag not set on attestation data", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseUnknownAttestationType()
        {
            var challenge = RandomGenerator.Default.GenerateBytes(128);
            var rp = "fido2.azurewebsites.net";
            var acd = new AttestedCredentialData(("00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-40-FE-6A-32-63-BE-37-D1-01-B1-2E-57-CA-96-6C-00-22-93-E4-19-C8-CD-01-06-23-0B-C6-92-E8-CC-77-12-21-F1-DB-11-5D-41-0F-82-6B-DB-98-AC-64-2E-B1-AE-B5-A8-03-D1-DB-C1-47-EF-37-1C-FD-B1-CE-B0-48-CB-2C-A5-01-02-03-26-20-01-21-58-20-A6-D1-09-38-5A-C7-8E-5B-F0-3D-1C-2E-08-74-BE-6D-BB-A4-0B-4F-2A-5F-2F-11-82-45-65-65-53-4F-67-28-22-58-20-43-E1-08-2A-F3-13-5B-40-60-93-79-AC-47-42-58-AA-B3-97-B8-86-1D-E4-41-B4-4E-83-08-5D-1C-6B-E0-D0").Split('-').Select(c => Convert.ToByte(c, 16)).ToArray());
            var authData = new AuthenticatorData(
                SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(rp)),
                AuthenticatorFlags.AT | AuthenticatorFlags.UP | AuthenticatorFlags.UV,
                0,
                acd,
                null
                ).ToByteArray();
            var clientDataJson = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject
                    (
                        new
                        {
                            Type = "webauthn.create",
                            Challenge = challenge,
                            Origin = rp,
                        }
                    )
                );
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = CBORObject.NewMap().Add("fmt", "testing").Add("attStmt", CBORObject.NewMap()).Add("authData", authData).EncodeToBytes(),
                    ClientDataJson = clientDataJson
                },
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
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam
                    {
                        Alg = COSE.Algorithm.ES256,
                        Type = PublicKeyCredentialType.PublicKey,
                    }
                },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("Missing or unknown attestation type", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAttestationResponseNotUniqueCredId()
        {
            var challenge = RandomGenerator.Default.GenerateBytes(128);
            var rp = "fido2.azurewebsites.net";
            var acd = new AttestedCredentialData(("00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-40-FE-6A-32-63-BE-37-D1-01-B1-2E-57-CA-96-6C-00-22-93-E4-19-C8-CD-01-06-23-0B-C6-92-E8-CC-77-12-21-F1-DB-11-5D-41-0F-82-6B-DB-98-AC-64-2E-B1-AE-B5-A8-03-D1-DB-C1-47-EF-37-1C-FD-B1-CE-B0-48-CB-2C-A5-01-02-03-26-20-01-21-58-20-A6-D1-09-38-5A-C7-8E-5B-F0-3D-1C-2E-08-74-BE-6D-BB-A4-0B-4F-2A-5F-2F-11-82-45-65-65-53-4F-67-28-22-58-20-43-E1-08-2A-F3-13-5B-40-60-93-79-AC-47-42-58-AA-B3-97-B8-86-1D-E4-41-B4-4E-83-08-5D-1C-6B-E0-D0").Split('-').Select(c => Convert.ToByte(c, 16)).ToArray());
            var authData = new AuthenticatorData(
                SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(rp)),
                AuthenticatorFlags.AT | AuthenticatorFlags.UP | AuthenticatorFlags.UV,
                0,
                acd,
                null
                ).ToByteArray();
            var clientDataJson = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject
                    (
                        new
                        {
                            Type = "webauthn.create",
                            Challenge = challenge,
                            Origin = rp,
                        }
                    )
                );
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = CBORObject.NewMap().Add("fmt", "none").Add("attStmt", CBORObject.NewMap()).Add("authData", authData).EncodeToBytes(),
                    ClientDataJson = clientDataJson
                },
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
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam
                    {
                        Alg = COSE.Algorithm.ES256,
                        Type = PublicKeyCredentialType.PublicKey,
                    }
                },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
                return Task.FromResult(false);
            };

            var lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.Equal("CredentialId is not unique to this user", ex.Result.Message);
        }

        [Fact]
        public void TestAuthenticatorAssertionRawResponse()
        {
            var challenge = RandomGenerator.Default.GenerateBytes(128);
            var clientDataJson = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject
                    (
                        new
                        {
                            Type = "webauthn.get",
                            Challenge = challenge,
                            Origin = "fido2.azurewebsites.net",
                        }
                    )
                );

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
                    AuthenticatorSelection = true,
                    BiometricAuthenticatorPerformanceBounds = true,
                    GenericTransactionAuthorization = new byte[] { 0xf1, 0xd0 },
                    SimpleTransactionAuthorization = "test",
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    Location = new GeoCoordinatePortable.GeoCoordinate(42.523714, -71.040860),
                    UserVerificationIndex = new byte[] { 0xf1, 0xd0 },
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
            Assert.True(assertionResponse.Extensions.AuthenticatorSelection);
            Assert.True(assertionResponse.Extensions.BiometricAuthenticatorPerformanceBounds);
            Assert.True(assertionResponse.Extensions.GenericTransactionAuthorization.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
            Assert.Equal("test", assertionResponse.Extensions.SimpleTransactionAuthorization);
            Assert.Equal(assertionResponse.Extensions.Extensions, new string[] { "foo", "bar" });
            Assert.Equal("test", assertionResponse.Extensions.Example);
            Assert.Equal(42.523714, assertionResponse.Extensions.Location.Latitude);
            Assert.Equal(-71.040860, assertionResponse.Extensions.Location.Longitude);
            Assert.True(assertionResponse.Extensions.UserVerificationIndex.SequenceEqual(new byte[] { 0xf1, 0xd0 }));
            Assert.Equal((ulong)4, assertionResponse.Extensions.UserVerificationMethod[0][0]);
        }
    }
}
