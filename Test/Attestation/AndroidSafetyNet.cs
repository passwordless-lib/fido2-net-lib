using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using fido2_net_lib.Test;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PeterO.Cbor;
using Xunit;

namespace Test.Attestation
{
    public class AndroidSafetyNet : Fido2Tests.Attestation
    {
        public AndroidSafetyNet()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "android-safetynet");
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

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

                    var serial = new byte[12];
                    RandomNumberGenerator.Fill(serial);

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

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                    List<Claim> claims = new List<Claim>
                    {
                        new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                        new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                        new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    { 
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));
                }
            }
        }
        
        [Fact]
        public async void TestAndroidSafetyNet()
        {
            var res = await MakeAttestationResponse();
            Assert.Equal(string.Empty, res.ErrorMessage);
            Assert.Equal("ok", res.Status);
            Assert.Equal(_aaguid, res.Result.Aaguid);
            Assert.Equal(_signCount, res.Result.Counter);
            Assert.Equal("android-safetynet", res.Result.CredType);
            Assert.Equal(_credentialID, res.Result.CredentialId);
            Assert.Null(res.Result.ErrorMessage);
            Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
            Assert.Null(res.Result.Status);
            Assert.Equal("Test User", res.Result.User.DisplayName);
            Assert.Equal(Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id);
            Assert.Equal("testuser", res.Result.User.Name);
        }

        [Fact]
        public async void TestAndroidSafetyNetRSA()
        {
            var param = Fido2Tests._validCOSEParameters[3];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using (var rsaRoot = RSA.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                rootRequest.CertificateExtensions.Add(caExt);

                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var rsaAtt = RSA.Create())
                {
                    var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    byte[] serial = new byte[12];
                    RandomNumberGenerator.Fill(serial);

                    using (X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                    }

                    var rsaparams = rsaAtt.ExportParameters(true);

                    var cpk = CBORObject.NewMap();
                    cpk.Add(COSE.KeyCommonParameter.KeyType, (COSE.KeyType)param[0]);
                    cpk.Add(COSE.KeyCommonParameter.Alg, (COSE.Algorithm)param[1]);
                    cpk.Add(COSE.KeyTypeParameter.N, rsaparams.Modulus);
                    cpk.Add(COSE.KeyTypeParameter.E, rsaparams.Exponent);

                    _credentialPublicKey = new CredentialPublicKey(cpk);

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                    List<Claim> claims = new List<Claim>
                    {
                        new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                        new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                        new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsaAtt), SecurityAlgorithms.RsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Set("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));

                    var res = await MakeAttestationResponse();
                    Assert.Equal(string.Empty, res.ErrorMessage);
                    Assert.Equal("ok", res.Status);
                    Assert.Equal(_aaguid, res.Result.Aaguid);
                    Assert.Equal(_signCount, res.Result.Counter);
                    Assert.Equal("android-safetynet", res.Result.CredType);
                    Assert.Equal(_credentialID, res.Result.CredentialId);
                    Assert.Null(res.Result.ErrorMessage);
                    Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
                    Assert.Null(res.Result.Status);
                    Assert.Equal("Test User", res.Result.User.DisplayName);
                    Assert.Equal(Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id);
                    Assert.Equal("testuser", res.Result.User.Name);
                }
            }
        }

        [Fact]
        public void TestAndroidSafetyNetVerNotString()
        {
            _attestationObject["attStmt"].Set("ver", 1);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid version in SafetyNet data", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetVerMissing()
        {
            _attestationObject["attStmt"].Set("ver", null);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid version in SafetyNet data", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetVerStrLenZero()
        {
            _attestationObject["attStmt"].Set("ver", "");
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid version in SafetyNet data", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseMissing()
        {
            _attestationObject["attStmt"].Set("response", null);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid response in SafetyNet data", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseNotByteString()
        {
            _attestationObject["attStmt"].Set("response", "telephone");
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid response in SafetyNet data", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseByteStringLenZero()
        {
            _attestationObject["attStmt"].Set("response", new byte[] { });
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Invalid response in SafetyNet data", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyResponseWhitespace()
        {
            _attestationObject["attStmt"].Set("response", Encoding.UTF8.GetBytes(" "));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("SafetyNet response null or whitespace", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetMalformedResponseJWT()
        {
            var response = _attestationObject["attStmt"]["response"].GetByteString();
            var responseJWT = Encoding.UTF8.GetString(response);
            var jwtParts = responseJWT.Split('.');
            _attestationObject["attStmt"].Set("response", Encoding.UTF8.GetBytes(jwtParts.First()));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("SafetyNet response JWT does not have the 3 expected components", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseJWTMissingX5c()
        {
            var response = _attestationObject["attStmt"]["response"].GetByteString();
            var jwtParts = Encoding.UTF8.GetString(response).Split('.');
            var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(jwtParts.First())));
            jwtHeaderJSON.Remove("x5c");
            jwtParts[0] = Base64Url.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
            response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
            _attestationObject["attStmt"].Set("response", response);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("SafetyNet response JWT header missing x5c", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseJWTX5cNoKeys()
        {
            var response = _attestationObject["attStmt"]["response"].GetByteString();
            var jwtParts = Encoding.UTF8.GetString(response).Split('.');
            var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(jwtParts.First())));
            jwtHeaderJSON.Remove("x5c");
            jwtHeaderJSON.Add("x5c", JToken.FromObject(new List<string> {  }));
            jwtParts[0] = Base64Url.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
            response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
            _attestationObject["attStmt"].Set("response", response);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("No keys were present in the TOC header in SafetyNet response JWT", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetJwtInvalid()
        {
            var response = _attestationObject["attStmt"]["response"].GetByteString();
            var jwtParts = Encoding.UTF8.GetString(response).Split('.');
            var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(jwtParts.First())));
            jwtHeaderJSON.Remove("x5c");
            byte[] x5c = null;
            using (var ecdsaAtt = ECDsa.Create())
            {
                var attRequest = new CertificateRequest(new X500DistinguishedName("CN=fakeattest.android.com"), ecdsaAtt, HashAlgorithmName.SHA256);

                var serial = new byte[12];
                RandomNumberGenerator.Fill(serial);

                using (X509Certificate2 publicOnly = attRequest.CreateSelfSigned(
                    DateTimeOffset.UtcNow,
                    DateTimeOffset.UtcNow.AddDays(2)))
                {
                    x5c = publicOnly.RawData;
                }
            }

            jwtHeaderJSON.Add("x5c", JToken.FromObject(new List<string> { Convert.ToBase64String(x5c) }));
            jwtParts[0] = Base64Url.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
            response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
            _attestationObject["attStmt"].Set("response", response);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.StartsWith("SafetyNet response security token validation failed", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseClaimTimestampExpired()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

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

                    var serial = new byte[12];
                    RandomNumberGenerator.Fill(serial);

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

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                    var claims = new List<Claim>
                    {
                        new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                        new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                        new Claim("timestampMs", DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Set("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.StartsWith("SafetyNet timestampMs must be present and between one minute ago and now, got:", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseClaimTimestampNotYetValid()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

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
                    RandomNumberGenerator.Fill(serial);

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

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                    List<Claim> claims = new List<Claim>
                    {
                        new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                        new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                        new Claim("timestampMs", DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Set("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.StartsWith("SafetyNet timestampMs must be present and between one minute ago and now, got:", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseClaimTimestampMissing()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

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
                    RandomNumberGenerator.Fill(serial);

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

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                    List<Claim> claims = new List<Claim>
                    {
                        new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                        new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Set("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.StartsWith("SafetyNet timestampMs must be present and between one minute ago and now, got:", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseClaimNonceMissing()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

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
                    RandomNumberGenerator.Fill(serial);
                   
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

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                    List<Claim> claims = new List<Claim>
                    {
                        new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                        new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Set("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Nonce value not found in SafetyNet attestation", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseClaimNonceInvalid()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

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

                    var serial = new byte[12];
                    RandomNumberGenerator.Fill(serial);

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

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);
                    attToBeSigned[^1] ^= 0xff;

                    var claims = new List<Claim>
                    {
                        new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                        new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                        new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Set("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.StartsWith("SafetyNet response nonce / hash value mismatch", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetResponseClaimNonceNotBase64String()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

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

                    var serial = new byte[12];
                    RandomNumberGenerator.Fill(serial);

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

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                    List<Claim> claims = new List<Claim>
                    {
                        new Claim("nonce", "n0tbase_64/str!ng" , ClaimValueTypes.String),
                        new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                        new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Set("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Nonce value not base64string in SafetyNet attestation", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetAttestationCertSubjectInvalid()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=sunshine.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

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

                    var serial = new byte[12];
                    RandomNumberGenerator.Fill(serial);

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

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                    List<Claim> claims = new List<Claim>
                    {
                        new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                        new Claim("ctsProfileMatch", bool.TrueString, ClaimValueTypes.Boolean),
                        new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Set("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.StartsWith("SafetyNet attestation cert DnsName invalid", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetCtsProfileMatchMissing()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

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

                    var serial = new byte[12];
                    RandomNumberGenerator.Fill(serial);

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

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                    var claims = new List<Claim>
                    {
                        new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                        new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Set("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("SafetyNet response ctsProfileMatch missing", ex.Result.Message);
        }

        [Fact]
        public void TestAndroidSafetyNetCtsProfileMatchFalse()
        {
            var param = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=attest.android.com, OU=SafetyNet Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

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

                    var serial = new byte[12];
                    RandomNumberGenerator.Fill(serial);

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

                    var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                    List<Claim> claims = new List<Claim>
                    {
                        new Claim("nonce", Convert.ToBase64String(attToBeSigned) , ClaimValueTypes.String),
                        new Claim("ctsProfileMatch", bool.FalseString, ClaimValueTypes.Boolean),
                        new Claim("timestampMs", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(), ClaimValueTypes.Integer64)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsaAtt), SecurityAlgorithms.EcdsaSha256Signature)
                    };

                    JwtSecurityToken securityToken = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);
                    securityToken.Header.Add(JwtHeaderParameterNames.X5c, new[] { attestnCert.RawData, root.RawData });

                    string strToken = "";
                    if (tokenHandler.CanWriteToken)
                    {
                        strToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
                    }

                    _attestationObject.Set("attStmt", CBORObject.NewMap()
                        .Add("ver", "F1D0")
                        .Add("response", Encoding.UTF8.GetBytes(strToken)));
                }
            }
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("SafetyNet response ctsProfileMatch false", ex.Result.Message);
        }
    }
}
