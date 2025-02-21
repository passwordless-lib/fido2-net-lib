using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Fido2NetLib.Serialization;

using NSec.Cryptography;

namespace Test;

public class AuthenticatorResponseTests
{
    [Fact]
    public void CanDeserialize()
    {
        var response = JsonSerializer.Deserialize<AuthenticatorResponse>("""{"type":"webauthn.get","challenge":"J4fjxBV-BNywGRJRm8JZ7znvdiZo9NINObNBpnKnJQEOtplTMF0ERuIrzrkeoO-dNMoeMZjhzqfar7eWRANvPeNFPrB5Q6zlS1ZFPf37F3suIwpXi9NCpFA_RlBSiygLmvcIOa57_QHubZQD3cv0UWtRTLslJjmgumphMc7EFN8","origin":"https://www.passwordless.dev"}""");

        Assert.Equal("webauthn.get", response.Type);
        Assert.Equal(Base64Url.DecodeFromChars("J4fjxBV-BNywGRJRm8JZ7znvdiZo9NINObNBpnKnJQEOtplTMF0ERuIrzrkeoO-dNMoeMZjhzqfar7eWRANvPeNFPrB5Q6zlS1ZFPf37F3suIwpXi9NCpFA_RlBSiygLmvcIOa57_QHubZQD3cv0UWtRTLslJjmgumphMc7EFN8"), response.Challenge);
        Assert.Equal("https://www.passwordless.dev", response.Origin);
    }

    [Theory]
    [InlineData("https://www.passwordless.dev", "https://www.passwordless.dev")]
    [InlineData("https://www.passwordless.dev:443", "https://www.passwordless.dev:443")]
    [InlineData("https://www.passwordless.dev", "https://www.passwordless.dev:443")]
    [InlineData("https://www.passwordless.dev:443", "https://www.passwordless.dev")]
    [InlineData("https://www.passwordless.dev:443/foo/bar.html", "https://www.passwordless.dev:443/foo/bar.html")]
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
    [InlineData("foo://bar:321/path", "foo://bar:321/path")]
    [InlineData("http://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]")]
    [InlineData("http://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]:80")]
    [InlineData("https://[0:0:0:0:0:0:0:1]", "https://[0:0:0:0:0:0:0:1]")]
    [InlineData("https://[0:0:0:0:0:0:0:1]", "https://[0:0:0:0:0:0:0:1]:443")]
    public async Task TestAuthenticatorOriginsAsync(string origin, string expectedOrigin)
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = origin;
        var acd = AttestedCredentialData.Parse(Convert.FromHexString("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0"));
        var authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(origin)),
            AuthenticatorFlags.UP | AuthenticatorFlags.AT,
            0,
            acd
        ).ToByteArray();

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp
        });
        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "none" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                PubKeyCredParam.ES256
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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

        var lib = new Fido2(new Fido2Configuration()
        {
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { expectedOrigin },
        });

        var result = await lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        });
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
    public async Task TestAuthenticatorOriginsFail(string origin, string expectedOrigin)
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = origin;
        var acd = AttestedCredentialData.Parse(Convert.FromHexString("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0"));
        var authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(origin)),
            AuthenticatorFlags.UP | AuthenticatorFlags.AT,
            0,
            acd
        ).ToByteArray();
        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "none" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { expectedOrigin },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.StartsWith("Fully qualified origin", ex.Message);
    }

    [Fact]
    public void TestAuthenticatorAttestationRawResponse()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = "https://www.passwordless.dev",
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap().Encode(),
                ClientDataJson = clientDataJson
            },
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs
            {
                AppID = true,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                },
                PRF = new AuthenticationExtensionsPRFOutputs
                {
                    Enabled = true,
                    Results = new AuthenticationExtensionsPRFValues
                    {
                        First = [0xf1, 0xd0],
                        Second = [0xf1, 0xd0]
                    }
                }
            }
        };
        Assert.Equal(PublicKeyCredentialType.PublicKey, rawResponse.Type);
        Assert.Equal("8dA", rawResponse.Id);
        Assert.Equal([0xf1, 0xd0], rawResponse.RawId);
        Assert.Equal([0xa0], rawResponse.Response.AttestationObject);
        Assert.Equal(clientDataJson, rawResponse.Response.ClientDataJson);
        Assert.True(rawResponse.ClientExtensionResults.AppID);
        Assert.Equal(new string[] { "foo", "bar" }, rawResponse.ClientExtensionResults.Extensions);
        Assert.True(rawResponse.ClientExtensionResults.Example);
        Assert.Equal((ulong)4, rawResponse.ClientExtensionResults.UserVerificationMethod[0][0]);
        Assert.True(rawResponse.ClientExtensionResults.PRF.Enabled);
        Assert.Equal(rawResponse.ClientExtensionResults.PRF.Results.First, [0xf1, 0xd0]);
        Assert.Equal([0xf1, 0xd0], rawResponse.ClientExtensionResults.PRF.Results.Second);
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
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = null
        };

        var ex = Assert.Throws<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));
        Assert.Equal("Expected rawResponse, got null", ex.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[0])]
    public void TestAuthenticatorAttestationResponseAttestationObjectNull(byte[] value)
    {
        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = value,
                ClientDataJson = null!
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
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = value,
                ClientDataJson = null!
            }
        };

        var ex = Assert.Throws<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));
        Assert.Equal(Fido2ErrorMessages.InvalidAttestationObject, ex.Message);
        Assert.Equal(Fido2ErrorCode.InvalidAttestationObject, ex.Code);

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
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = value,
                ClientDataJson = null!
            }
        };

        var ex = Assert.Throws<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));

        Assert.Equal(Fido2ErrorCode.MalformedAttestationObject, ex.Code);
        Assert.Equal(Fido2ErrorMessages.MalformedAttestationObject, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAttestationResponseInvalidType()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.get",
            Challenge = challenge,
            Origin = rp,
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", new AuthenticatorData(new byte[32], default, 0, null, null).ToByteArray() }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.Same(Fido2ErrorMessages.AttestationResponseTypeNotWebAuthnGet, ex.Message);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", new byte[0])]
    public async Task TestAuthenticatorAttestationResponseInvalidRawId(string value, byte[] rawValue)
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp,
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = value,
            RawId = rawValue,
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", new AuthenticatorData(new byte[32], default, 0, null, null).ToByteArray() }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.Same(Fido2ErrorMessages.AttestationResponseIdMissing, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAttestationResponseInvalidRawType()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp,
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.Invalid,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", new AuthenticatorData(new byte[32], default, 0, null, null).ToByteArray() }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.Equal("AttestationResponse type must be 'public-key'", ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAttestationResponseRpidMismatch()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authData = new AuthenticatorData(
            SHA256.HashData("passwordless.dev"u8),
            AuthenticatorFlags.UV,
            0,
            null
        ).ToByteArray();

        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.Equal(Fido2ErrorCode.InvalidRpidHash, ex.Code);
        Assert.Equal(Fido2ErrorMessages.InvalidRpidHash, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAttestationResponseNotUserPresentAsync()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.UV,
            0,
            null
        ).ToByteArray();

        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),

                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));

        Assert.Equal(Fido2ErrorCode.UserPresentFlagNotSet, ex.Code);
        Assert.Equal(Fido2ErrorMessages.UserPresentFlagNotSet, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAttestationResponseBackupEligiblePolicyRequired()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.UP | AuthenticatorFlags.UV,
            0,
            null
        ).ToByteArray();

        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp,
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
            User = new Fido2User
            {
                Name = "testuser",
                Id = "testuser"u8.ToArray(),
                DisplayName = "Test User"
            },
            Timeout = 60000,
        };

        IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var lib = new Fido2(new Fido2Configuration
        {
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.BackupEligibilityRequirementNotMet, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAttestationResponseBackupEligiblePolicyDisallowed()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE,
            0,
            null
        ).ToByteArray();

        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp,
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Disallowed,
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.BackupEligibilityRequirementNotMet, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAttestationResponseNoAttestedCredentialData()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.UP | AuthenticatorFlags.UV,
            0,
            null
        ).ToByteArray();

        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp,
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.Equal("Attestation flag not set on attestation data", ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAttestationResponseUnknownAttestationType()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var acd = AttestedCredentialData.Parse(Convert.FromHexString("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0"));
        var authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.AT | AuthenticatorFlags.UP | AuthenticatorFlags.UV,
            0,
            acd
        ).ToByteArray();

        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.Equal("Unknown attestation type. Was 'testing'", ex.Message);
        Assert.Equal(Fido2ErrorCode.UnknownAttestationType, ex.Code);
    }

    [Fact]
    public async Task TestAuthenticatorAttestationResponseNotUniqueCredId()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var acd = AttestedCredentialData.Parse(Convert.FromHexString("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0"));
        var authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.AT | AuthenticatorFlags.UP | AuthenticatorFlags.UV,
            0,
            acd
        ).ToByteArray();
        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "none" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            return Task.FromResult(false);
        };

        var lib = new Fido2(new Fido2Configuration
        {
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.Equal("CredentialId is not unique to this user", ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAttestationResponseUVRequired()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var acd = AttestedCredentialData.Parse(Convert.FromHexString("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0"));
        var authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.AT | AuthenticatorFlags.UP,
            0,
            acd
        ).ToByteArray();
        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = rp
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap {
                    { "fmt", "none" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Required,
            },
            Challenge = challenge,
            PubKeyCredParams =
            [
                new PubKeyCredParam(COSE.Algorithm.ES256)
            ],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
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
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = callback
        }));
        Assert.Equal("User Verified flag not set in authenticator data and user verification was required", ex.Message);
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

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse
        {
            AuthenticatorData = [0xf1, 0xd0],
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs
            {
                AppID = true,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
                PRF = new AuthenticationExtensionsPRFOutputs
                {
                    Enabled = true,
                    Results = new AuthenticationExtensionsPRFValues
                    {
                        First = [0xf1, 0xd0],
                        Second = [0xf1, 0xd0]
                    }
                }
            }
        };
        Assert.Equal(PublicKeyCredentialType.PublicKey, assertionResponse.Type);
        Assert.Equal("8dA", assertionResponse.Id);
        Assert.Equal([0xf1, 0xd0], assertionResponse.RawId);
        Assert.Equal([0xf1, 0xd0], assertionResponse.Response.AuthenticatorData);
        Assert.Equal([0xf1, 0xd0], assertionResponse.Response.Signature);
        Assert.Equal(clientDataJson, assertionResponse.Response.ClientDataJson);
        Assert.Equal([0xf1, 0xd0], assertionResponse.Response.UserHandle);
        Assert.True(assertionResponse.ClientExtensionResults.AppID);
        Assert.Equal(new string[] { "foo", "bar" }, assertionResponse.ClientExtensionResults.Extensions);
        Assert.True(assertionResponse.ClientExtensionResults.Example);
        Assert.Equal((ulong)4, assertionResponse.ClientExtensionResults.UserVerificationMethod[0][0]);
        Assert.True(assertionResponse.ClientExtensionResults.PRF.Enabled);
        Assert.Equal([0xf1, 0xd0], assertionResponse.ClientExtensionResults.PRF.Results.First);
        Assert.Equal([0xf1, 0xd0], assertionResponse.ClientExtensionResults.PRF.Results.Second);

    }

    [Fact]
    public async Task TestAuthenticatorAssertionTypeNotPublicKey()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0]
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse
        {
            Response = assertion,
            Type = PublicKeyCredentialType.Invalid,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                }
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.AssertionResponseNotPublicKey, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionIdMissing()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.AssertionResponseIdMissing, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionRawIdMissing()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";

        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse()
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.AssertionResponseRawIdMissing, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionUserHandleEmpty()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = []
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse()
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.UserHandleIsEmpty, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionUserHandleNotOwnerOfPublicKey()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse()
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(false);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.UserHandleNotOwnerOfPublicKey, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionTypeNotWebAuthnGet()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.create",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.AssertionResponseTypeNotWebAuthnGet, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionAppId()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";

        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Extensions = new() { AppID = "https://foo.bar" },
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0]
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse()
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
            {
                AppID = true,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.InvalidRpidHash, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionInvalidRpIdHash()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";

        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes("https://foo.bar")), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse()
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.InvalidRpidHash, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionUPRequirementNotMet()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";

        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            UserVerification = UserVerificationRequirement.Required,
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), 0, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                }
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.UserPresentFlagNotSet, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionUVPolicyNotMet()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";

        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            UserVerification = UserVerificationRequirement.Required,
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                }
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.UserVerificationRequirementNotMet, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionBEPolicyRequired()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse()
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.BackupEligibilityRequirementNotMet, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionBEPolicyDisallow()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse()
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Disallowed,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.BackupEligibilityRequirementNotMet, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionBSPolicyRequired()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse()
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackedUpCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.BackupStateRequirementNotMet, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionBSPolicyDisallow()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";
        var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BS, 0, null).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                }
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            BackedUpCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Disallowed,
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.BackupStateRequirementNotMet, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionStoredPublicKeyMissing()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";

        var authenticatorResponse = new AuthenticatorResponse(
           type: "webauthn.get",
           challenge: challenge,
           origin: rp
       );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null, new Extensions(new byte[] { 0x42 })).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse()
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = null,
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.MissingStoredPublicKey, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionInvalidSignature()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";

        var authenticatorResponse = new AuthenticatorResponse(
           type: "webauthn.get",
           challenge: challenge,
           origin: rp
       );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null, new Extensions(new byte[] { 0x42 })).ToByteArray(),
            Signature = [0xf1, 0xd0],
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse()
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                }
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp }
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        fido2_net_lib.Test.Fido2Tests.MakeEdDSA(out _, out var publicKey, out var privateKey);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = fido2_net_lib.Test.Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519, publicKey).GetBytes(),
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.InvalidSignature, ex.Message);
    }

    [Fact]
    public async Task TestAuthenticatorAssertionSignCountSignature()
    {
        var challenge = RandomNumberGenerator.GetBytes(128);
        var rp = "https://www.passwordless.dev";

        var authenticatorResponse = new AuthenticatorResponse(
           type: "webauthn.get",
           challenge: challenge,
           origin: rp
       );

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = rp,
            AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor([0xf1, 0xd0])
            }
        };

        var authData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 1, null, new Extensions(new byte[] { 0x42 })).ToByteArray();

        fido2_net_lib.Test.Fido2Tests.MakeEdDSA(out _, out var publicKey, out var expandedPrivateKey);
        Key privateKey = Key.Import(SignatureAlgorithm.Ed25519, expandedPrivateKey, KeyBlobFormat.RawPrivateKey);
        var cpk = fido2_net_lib.Test.Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519, publicKey);

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse
        {
            AuthenticatorData = authData,
            Signature = SignatureAlgorithm.Ed25519.Sign(privateKey, [.. authData, .. SHA256.HashData(clientDataJson)]),
            ClientDataJson = clientDataJson,
            UserHandle = [0xf1, 0xd0],
        };

        var assertionResponse = new AuthenticatorAssertionRawResponse
        {
            Response = assertion,
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = [0xf1, 0xd0],
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
            {
                AppID = false,
                Extensions = ["foo", "bar"],
                Example = true,
                UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = options,
            StoredPublicKey = cpk.GetBytes(),
            StoredSignatureCounter = 2,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        }));
        Assert.Equal(Fido2ErrorMessages.SignCountIsLessThanSignatureCounter, ex.Message);
    }
}
