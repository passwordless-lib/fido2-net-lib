using System.Buffers.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Test.Attestation;

public class AndroidSafetyNet : Fido2Tests.Attestation
{
    public AndroidSafetyNet()
    {
        _attestationObject = new CborMap { { "fmt", "android-safetynet" } };
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var ecdsaRoot = ECDsa.Create();
        var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(caExt);

        ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
        using (root = rootRequest.CreateSelfSigned(notBefore, notAfter))
        using (var ecdsaAtt = ECDsa.Create(eCCurve))
        {
            var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

            var serial = RandomNumberGenerator.GetBytes(12);

            using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
            {
                attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
            }

            var ecParams = ecdsaAtt.ExportParameters(true);

            var cpk = new CborMap {
                { COSE.KeyCommonParameter.KeyType, type },
                { COSE.KeyCommonParameter.Alg, alg },
                { COSE.KeyTypeParameter.X, ecParams.Q.X },
                { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                { COSE.KeyTypeParameter.Crv, curve }
            };

            var x = (byte[])cpk[COSE.KeyTypeParameter.X];
            var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

            _credentialPublicKey = new CredentialPublicKey(cpk);

            var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

            var claims = new[]
            {
                new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
            };

            var tokenHandler = new JsonWebTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                AdditionalHeaderClaims = new Dictionary<string, object>()
                {
                    {
                        JwtHeaderParameterNames.X5c, new[] {
                            Convert.ToBase64String(attestnCert.RawData),
                            Convert.ToBase64String(root.RawData)
                        }
                    }
                },
                Subject = new ClaimsIdentity(claims),
                SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
            };

            string securityToken = tokenHandler.CreateToken(tokenDescriptor);

            _attestationObject.Add("attStmt", new CborMap {
                { "ver", "F1D0" },
                { "response", Encoding.UTF8.GetBytes(securityToken) }
            });
        }
    }

    [Fact]
    public async Task TestAndroidSafetyNet()
    {
        var credential = await MakeAttestationResponseAsync();
        Assert.Equal(_aaguid, credential.AaGuid);
        Assert.Equal(_signCount, credential.SignCount);
        Assert.Equal("android-safetynet", credential.AttestationFormat);
        Assert.Equal(_credentialID, credential.Id);
        Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
        Assert.Equal("Test User", credential.User.DisplayName);
        Assert.Equal("testuser"u8.ToArray(), credential.User.Id);
        Assert.Equal("testuser", credential.User.Name);
        Assert.Equal([AuthenticatorTransport.Internal], credential.Transports);
    }

    [Fact]
    public async Task TestAndroidSafetyNetRSA()
    {
        var (type, alg, _) = Fido2Tests._validCOSEParameters[3];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using var rsaRoot = RSA.Create();
        var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(caExt);

        using (root = rootRequest.CreateSelfSigned(
            notBefore,
            notAfter))

        using (var rsaAtt = RSA.Create())
        {
            var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            byte[] serial = RandomNumberGenerator.GetBytes(12);

            using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
            {
                attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
            }

            var rsaParams = rsaAtt.ExportParameters(true);

            var cpk = new CborMap
            {
                { COSE.KeyCommonParameter.KeyType, type },
                { COSE.KeyCommonParameter.Alg, alg },
                { COSE.KeyTypeParameter.N, rsaParams.Modulus },
                { COSE.KeyTypeParameter.E, rsaParams.Exponent }
            };

            _credentialPublicKey = new CredentialPublicKey(cpk);

            var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

            var claims = new[] {
                new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
            };

            var tokenHandler = new JsonWebTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsaAtt), SecurityAlgorithms.RsaSha256Signature),
                AdditionalHeaderClaims = new Dictionary<string, object>
                {
                    {
                        JwtHeaderParameterNames.X5c, new[] {
                            Convert.ToBase64String(attestnCert.RawData),
                            Convert.ToBase64String(root.RawData)
                        }
                    }
                }
            };

            string securityToken = tokenHandler.CreateToken(tokenDescriptor);

            _attestationObject.Set("attStmt", new CborMap {
                { "ver", "F1D0" },
                { "response", Encoding.UTF8.GetBytes(securityToken) }
            });

            var credential = await MakeAttestationResponseAsync();
            Assert.Equal(_aaguid, credential.AaGuid);
            Assert.Equal(_signCount, credential.SignCount);
            Assert.Equal("android-safetynet", credential.AttestationFormat);
            Assert.Equal(_credentialID, credential.Id);
            Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
            Assert.Equal("Test User", credential.User.DisplayName);
            Assert.Equal("testuser"u8.ToArray(), credential.User.Id);
            Assert.Equal("testuser", credential.User.Name);
        }
    }

    [Fact]
    public async Task TestAndroidSafetyNetVerNotString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("ver", new CborInteger(1));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid version in SafetyNet data", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetVerMissing()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("ver", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid version in SafetyNet data", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetVerStrLenZero()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("ver", new CborTextString(""));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid version in SafetyNet data", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseMissing()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", CborNull.Instance);
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid response in SafetyNet data", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseNotByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborTextString("telephone"));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid response in SafetyNet data", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseByteStringLenZero()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString([]));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Invalid response in SafetyNet data", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyResponseWhitespace()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(" "u8.ToArray()));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Same(Fido2ErrorMessages.MalformedSafetyNetJwt, ex.Message);
    }

    [Theory]
    [InlineData(".")]
    [InlineData("x.x")]
    [InlineData("x.x.")]
    public async Task TestAndroidSafetyNetMalformedResponseJWT(string text)
    {
        var response = (byte[])_attestationObject["attStmt"]["response"];
        var responseJWT = Encoding.UTF8.GetString(response);

        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(Encoding.UTF8.GetBytes(text)));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Same(Fido2ErrorMessages.MalformedSafetyNetJwt, ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseJWTMissingX5c()
    {
        var response = (byte[])_attestationObject["attStmt"]["response"];
        var jwtParts = Encoding.UTF8.GetString(response).Split('.');
        var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(jwtParts.First())));
        jwtHeaderJSON.Remove("x5c");
        jwtParts[0] = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
        response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(response));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("SafetyNet response JWT header missing x5c", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseJWTX5cNoKeys()
    {
        var response = (byte[])_attestationObject["attStmt"]["response"];
        var jwtParts = Encoding.UTF8.GetString(response).Split('.');
        var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(jwtParts.First())));
        jwtHeaderJSON.Remove("x5c");
        jwtHeaderJSON.Add("x5c", JToken.FromObject(new List<string> { }));
        jwtParts[0] = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
        response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(response));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("No keys were present in the TOC header in SafetyNet response JWT", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseJWTX5cInvalidString()
    {
        var response = (byte[])_attestationObject["attStmt"]["response"];
        var jwtParts = Encoding.UTF8.GetString(response).Split('.');
        var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(jwtParts.First())));
        jwtHeaderJSON.Remove("x5c");
        jwtHeaderJSON.Add("x5c", JToken.FromObject(new List<string> { "RjFEMA==" }));
        jwtParts[0] = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
        response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(response));
        var ex = await Assert.ThrowsAnyAsync<Exception>(MakeAttestationResponseAsync);
        Assert.Equal("Could not parse X509 certificate", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetJwtInvalid()
    {
        var response = (byte[])_attestationObject["attStmt"]["response"];
        var jwtParts = Encoding.UTF8.GetString(response).Split('.');
        var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(jwtParts.First())));
        jwtHeaderJSON.Remove("x5c");
        byte[] x5c = null;
        using (var ecdsaAtt = ECDsa.Create())
        {
            var attRequest = new CertificateRequest(new X500DistinguishedName("CN=fakeattest.android.com"), ecdsaAtt, HashAlgorithmName.SHA256);

            byte[] serial = RandomNumberGenerator.GetBytes(12);

            using X509Certificate2 publicOnly = attRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddDays(2));
            x5c = publicOnly.RawData;
        }

        jwtHeaderJSON.Add("x5c", JToken.FromObject(new List<string> { Convert.ToBase64String(x5c) }));
        jwtParts[0] = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
        response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(response));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.StartsWith("SafetyNet response security token validation failed", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseClaimTimestampExpired()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using (var ecdsaRoot = ECDsa.Create())
        {
            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(caExt);

            ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
            using (root = rootRequest.CreateSelfSigned(notBefore, notAfter))

            using (var ecdsaAtt = ECDsa.Create(eCCurve))
            {
                var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                byte[] serial = RandomNumberGenerator.GetBytes(12);

                using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
                {
                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                }

                var ecParams = ecdsaAtt.ExportParameters(true);

                var cpk = new CborMap {
                    { COSE.KeyCommonParameter.KeyType, type },
                    { COSE.KeyCommonParameter.Alg, alg },
                    { COSE.KeyTypeParameter.X, ecParams.Q.X },
                    { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                    { COSE.KeyTypeParameter.Crv, curve }
                };

                var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                var claims = new[]
                {
                    new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                    new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                    new Claim("timestampMs", DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                };

                var tokenHandler = new JsonWebTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature),
                    AdditionalHeaderClaims = new Dictionary<string, object>
                    {
                        {
                            JwtHeaderParameterNames.X5c, new[] {
                                Convert.ToBase64String(attestnCert.RawData),
                                Convert.ToBase64String(root.RawData)
                            }
                        }
                    }
                };

                string securityToken = tokenHandler.CreateToken(tokenDescriptor);

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(securityToken) }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.StartsWith("SafetyNet timestampMs must be between one minute ago and now, got:", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseClaimTimestampNotYetValid()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using (var ecdsaRoot = ECDsa.Create())
        {
            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(caExt);

            ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
            using (root = rootRequest.CreateSelfSigned(notBefore, notAfter))
            using (var ecdsaAtt = ECDsa.Create(eCCurve))
            {
                var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                byte[] serial = RandomNumberGenerator.GetBytes(12);

                using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
                {
                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                }

                var ecParams = ecdsaAtt.ExportParameters(true);

                var cpk = new CborMap
                {
                    { COSE.KeyCommonParameter.KeyType, type },
                    { COSE.KeyCommonParameter.Alg, alg },
                    { COSE.KeyTypeParameter.X, ecParams.Q.X },
                    { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                    { COSE.KeyTypeParameter.Crv, curve }
                };

                var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                var claims = new[]
                {
                    new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                    new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                    new Claim("timestampMs", DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                };

                var tokenHandler = new JsonWebTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature),
                    AdditionalHeaderClaims = new Dictionary<string, object>
                    {
                        {
                            JwtHeaderParameterNames.X5c, new[] {
                                Convert.ToBase64String(attestnCert.RawData),
                                Convert.ToBase64String(root.RawData)
                            }
                        }
                    }
                };

                string securityToken = tokenHandler.CreateToken(tokenDescriptor);

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(securityToken) }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.StartsWith("SafetyNet timestampMs must be between one minute ago and now, got:", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseClaimTimestampMissing()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using (var ecdsaRoot = ECDsa.Create())
        {
            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(caExt);

            ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
            using (root = rootRequest.CreateSelfSigned(notBefore, notAfter))

            using (var ecdsaAtt = ECDsa.Create(eCCurve))
            {
                var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                byte[] serial = RandomNumberGenerator.GetBytes(12);

                using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
                {
                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                }

                var ecParams = ecdsaAtt.ExportParameters(true);

                var cpk = new CborMap
                {
                    { COSE.KeyCommonParameter.KeyType, type },
                    { COSE.KeyCommonParameter.Alg, alg },
                    { COSE.KeyTypeParameter.X, ecParams.Q.X },
                    { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                    { COSE.KeyTypeParameter.Crv, curve }
                };

                var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                var claims = new[]
                {
                    new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                    new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                };

                var tokenHandler = new JsonWebTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature),
                    AdditionalHeaderClaims = new Dictionary<string, object>
                    {
                        {
                            JwtHeaderParameterNames.X5c, new[] {
                                Convert.ToBase64String(attestnCert.RawData),
                                Convert.ToBase64String(root.RawData)
                            }
                        }
                    }
                };

                string securityToken = tokenHandler.CreateToken(tokenDescriptor);

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(securityToken) }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("SafetyNet timestampMs not found SafetyNet attestation", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseClaimNonceMissing()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using (var ecdsaRoot = ECDsa.Create())
        {
            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(caExt);

            ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
            using (root = rootRequest.CreateSelfSigned(notBefore, notAfter))

            using (var ecdsaAtt = ECDsa.Create(eCCurve))
            {
                var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                byte[] serial = RandomNumberGenerator.GetBytes(12);

                using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
                {
                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                }

                var ecParams = ecdsaAtt.ExportParameters(true);

                var cpk = new CborMap
                {
                    { COSE.KeyCommonParameter.KeyType, type },
                    { COSE.KeyCommonParameter.Alg, alg },
                    { COSE.KeyTypeParameter.X, ecParams.Q.X },
                    { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                    { COSE.KeyTypeParameter.Crv, curve }
                };

                var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                var claims = new[]
                {
                    new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                    new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                };

                var tokenHandler = new JsonWebTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature),
                    AdditionalHeaderClaims = new Dictionary<string, object>
                    {
                        {
                            JwtHeaderParameterNames.X5c, new[] {
                                Convert.ToBase64String(attestnCert.RawData),
                                Convert.ToBase64String(root.RawData)
                            }
                        }
                    }
                };

                string securityToken = tokenHandler.CreateToken(tokenDescriptor);

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(securityToken) }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Nonce value not found in SafetyNet attestation", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseClaimNonceInvalid()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using (var ecdsaRoot = ECDsa.Create())
        {
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

                using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
                {
                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                }

                var ecParams = ecdsaAtt.ExportParameters(true);

                var cpk = new CborMap
                {
                    { COSE.KeyCommonParameter.KeyType, type },
                    { COSE.KeyCommonParameter.Alg, alg },
                    { COSE.KeyTypeParameter.X, ecParams.Q.X },
                    { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                    { COSE.KeyTypeParameter.Crv, curve }
                };

                var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);
                attToBeSigned[^1] ^= 0xff;

                var claims = new[]
                {
                    new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                    new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                    new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                };

                var tokenHandler = new JsonWebTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature),
                    AdditionalHeaderClaims = new Dictionary<string, object>
                    {
                        {
                            JwtHeaderParameterNames.X5c, new[] {
                                Convert.ToBase64String(attestnCert.RawData),
                                Convert.ToBase64String(root.RawData)
                            }
                        }
                    }
                };

                string securityToken = tokenHandler.CreateToken(tokenDescriptor);

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(securityToken) }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.StartsWith("SafetyNet response nonce / hash value mismatch", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetResponseClaimNonceNotBase64String()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using (var ecdsaRoot = ECDsa.Create())
        {
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

                using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
                {
                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                }

                var ecParams = ecdsaAtt.ExportParameters(true);

                var cpk = new CborMap
                {
                    { COSE.KeyCommonParameter.KeyType, type },
                    { COSE.KeyCommonParameter.Alg, alg },
                    { COSE.KeyTypeParameter.X, ecParams.Q.X },
                    { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                    { COSE.KeyTypeParameter.Crv, curve }
                };

                var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                var claims = new[] {
                    new Claim("nonce", "n0tbase_64/str!ng" , ClaimValueTypes.String),
                    new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                    new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                };

                var tokenHandler = new JsonWebTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature),
                    AdditionalHeaderClaims = new Dictionary<string, object>
                    {
                        {
                            JwtHeaderParameterNames.X5c, new[] {
                                Convert.ToBase64String(attestnCert.RawData),
                                Convert.ToBase64String(root.RawData)
                            }
                        }
                    }
                };

                string securityToken = tokenHandler.CreateToken(tokenDescriptor);

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(securityToken) }
                });
            }
        }

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("Nonce value not base64string in SafetyNet attestation", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetAttestationCertSubjectInvalid()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=sunshine.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using (var ecdsaRoot = ECDsa.Create())
        {
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

                using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
                {
                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                }

                var ecParams = ecdsaAtt.ExportParameters(true);

                var cpk = new CborMap
                {
                    { COSE.KeyCommonParameter.KeyType, type },
                    { COSE.KeyCommonParameter.Alg, alg },
                    { COSE.KeyTypeParameter.X, ecParams.Q.X },
                    { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                    { COSE.KeyTypeParameter.Crv, curve }
                };

                var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                var claims = new[]
                {
                    new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                    new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                    new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                };

                var tokenHandler = new JsonWebTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature),
                    AdditionalHeaderClaims = new Dictionary<string, object>
                    {
                        {
                            JwtHeaderParameterNames.X5c, new[] {
                                Convert.ToBase64String(attestnCert.RawData),
                                Convert.ToBase64String(root.RawData)
                            }
                        }
                    }
                };

                string securityToken = tokenHandler.CreateToken(tokenDescriptor);

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(securityToken) }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.StartsWith("Invalid SafetyNet attestation cert DnsName", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetCtsProfileMatchMissing()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using (var ecdsaRoot = ECDsa.Create())
        {
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

                using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
                {
                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                }

                var ecParams = ecdsaAtt.ExportParameters(true);

                var cpk = new CborMap
                {
                    { COSE.KeyCommonParameter.KeyType, type },
                    { COSE.KeyCommonParameter.Alg, alg },
                    { COSE.KeyTypeParameter.X, ecParams.Q.X },
                    { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                    { COSE.KeyTypeParameter.Crv, curve }
                };

                var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                var claims = new[]
                {
                    new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                    new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                };

                var tokenHandler = new JsonWebTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature),
                    AdditionalHeaderClaims = new Dictionary<string, object>
                    {
                        {
                            JwtHeaderParameterNames.X5c, new[] {
                                Convert.ToBase64String(attestnCert.RawData),
                                Convert.ToBase64String(root.RawData)
                            }
                        }
                    }
                };

                string securityToken = tokenHandler.CreateToken(tokenDescriptor);

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(securityToken) }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("SafetyNet response ctsProfileMatch missing", ex.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetCtsProfileMatchFalse()
    {
        var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
        X509Certificate2 root, attestnCert;
        DateTimeOffset notBefore = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = notBefore.AddDays(2);
        var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

        using (var ecdsaRoot = ECDsa.Create())
        {
            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(caExt);

            ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
            using (root = rootRequest.CreateSelfSigned(notBefore, notAfter))
            using (var ecdsaAtt = ECDsa.Create(eCCurve))
            {
                var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                byte[] serial = RandomNumberGenerator.GetBytes(12);

                using (X509Certificate2 publicOnly = attRequest.Create(root, notBefore, notAfter, serial))
                {
                    attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                }

                var ecParams = ecdsaAtt.ExportParameters(true);

                var cpk = new CborMap
                {
                    { COSE.KeyCommonParameter.KeyType, type },
                    { COSE.KeyCommonParameter.Alg, alg },
                    { COSE.KeyTypeParameter.X, ecParams.Q.X },
                    { COSE.KeyTypeParameter.Y, ecParams.Q.Y },
                    { COSE.KeyTypeParameter.Crv, curve }
                };

                var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                var claims = new[]
                {
                    new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                    new Claim("ctsProfileMatch", bool.FalseString, ClaimValueTypes.Boolean),
                    new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                };

                var tokenHandler = new JsonWebTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature),
                    AdditionalHeaderClaims = new Dictionary<string, object>
                    {
                        {
                            JwtHeaderParameterNames.X5c, new[] {
                                Convert.ToBase64String(attestnCert.RawData),
                                Convert.ToBase64String(root.RawData)
                            }
                        }
                    }
                };

                string securityToken = tokenHandler.CreateToken(tokenDescriptor);

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(securityToken) }
                 });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);
        Assert.Equal("SafetyNet response ctsProfileMatch false", ex.Message);
    }
}
