using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

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

            _attestationObject.Add("attStmt", new CborMap {
                { "ver", "F1D0" },
                { "response", Encoding.UTF8.GetBytes(strToken) }
            });
        }
    }
    
    [Fact]
    public async void TestAndroidSafetyNet()
    {
        var res = await MakeAttestationResponseAsync();
        Assert.Equal(string.Empty, res.ErrorMessage);
        Assert.Equal("ok", res.Status);
        Assert.Equal(_aaguid, res.Result.AaGuid);
        Assert.Equal(_signCount, res.Result.SignCount);
        Assert.Equal("android-safetynet", res.Result.CredType);
        Assert.Equal(_credentialID, res.Result.Id);
        Assert.Null(res.Result.ErrorMessage);
        Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
        Assert.Null(res.Result.Status);
        Assert.Equal("Test User", res.Result.User.DisplayName);
        Assert.Equal("testuser"u8.ToArray(), res.Result.User.Id);
        Assert.Equal("testuser", res.Result.User.Name);
    }

    [Fact]
    public async void TestAndroidSafetyNetRSA()
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

            var claims = new List<Claim> {
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

            _attestationObject.Set("attStmt", new CborMap {
                { "ver", "F1D0" },
                { "response", Encoding.UTF8.GetBytes(strToken) }
            });

            var res = await MakeAttestationResponseAsync();
            Assert.Equal(string.Empty, res.ErrorMessage);
            Assert.Equal("ok", res.Status);
            Assert.Equal(_aaguid, res.Result.AaGuid);
            Assert.Equal(_signCount, res.Result.SignCount);
            Assert.Equal("android-safetynet", res.Result.CredType);
            Assert.Equal(_credentialID, res.Result.Id);
            Assert.Null(res.Result.ErrorMessage);
            Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
            Assert.Null(res.Result.Status);
            Assert.Equal("Test User", res.Result.User.DisplayName);
            Assert.Equal("testuser"u8.ToArray(), res.Result.User.Id);
            Assert.Equal("testuser", res.Result.User.Name);
        }
    }

    [Fact]
    public void TestAndroidSafetyNetVerNotString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("ver", new CborInteger(1));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid version in SafetyNet data", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetVerMissing()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("ver", CborNull.Instance);
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid version in SafetyNet data", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetVerStrLenZero()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("ver", new CborTextString(""));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid version in SafetyNet data", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseMissing()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", CborNull.Instance);
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid response in SafetyNet data", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseNotByteString()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborTextString("telephone"));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid response in SafetyNet data", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseByteStringLenZero()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(new byte[] { }));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Invalid response in SafetyNet data", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyResponseWhitespace()
    {
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(" "u8.ToArray()));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Same(Fido2ErrorMessages.MalformedSafetyNetJwt, ex.Result.Message);
    }

    [Theory]
    [InlineData(".")]
    [InlineData("x.x")]
    [InlineData("x.x.")]
    public void TestAndroidSafetyNetMalformedResponseJWT(string text)
    {
        var response = (byte[])_attestationObject["attStmt"]["response"];
        var responseJWT = Encoding.UTF8.GetString(response);

        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(Encoding.UTF8.GetBytes(text)));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Same(Fido2ErrorMessages.MalformedSafetyNetJwt, ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseJWTMissingX5c()
    {
        var response = (byte[])_attestationObject["attStmt"]["response"];
        var jwtParts = Encoding.UTF8.GetString(response).Split('.');
        var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(jwtParts.First())));
        jwtHeaderJSON.Remove("x5c");
        jwtParts[0] = Base64Url.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
        response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(response));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("SafetyNet response JWT header missing x5c", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseJWTX5cNoKeys()
    {
        var response = (byte[])_attestationObject["attStmt"]["response"];
        var jwtParts = Encoding.UTF8.GetString(response).Split('.');
        var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(jwtParts.First())));
        jwtHeaderJSON.Remove("x5c");
        jwtHeaderJSON.Add("x5c", JToken.FromObject(new List<string> {  }));
        jwtParts[0] = Base64Url.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
        response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(response));
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("No keys were present in the TOC header in SafetyNet response JWT", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseJWTX5cInvalidString()
    {
        var response = (byte[])_attestationObject["attStmt"]["response"];
        var jwtParts = Encoding.UTF8.GetString(response).Split('.');
        var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(jwtParts.First())));
        jwtHeaderJSON.Remove("x5c");
        jwtHeaderJSON.Add("x5c", JToken.FromObject(new List<string> { "RjFEMA=="}));
        jwtParts[0] = Base64Url.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
        response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(response));
        var ex = Assert.ThrowsAnyAsync<Exception>(async () => await MakeAttestationResponseAsync());
        Assert.Equal("Could not parse X509 certificate", ex.Result.Message);
    }

    [Fact]
    public async Task TestAndroidSafetyNetJwtInvalid()
    {
        var response = (byte[])_attestationObject["attStmt"]["response"];
        var jwtParts = Encoding.UTF8.GetString(response).Split('.');
        var jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(jwtParts.First())));
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
        jwtParts[0] = Base64Url.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwtHeaderJSON)));
        response = Encoding.UTF8.GetBytes(string.Join(".", jwtParts));
        var attStmt = (CborMap)_attestationObject["attStmt"];
        attStmt.Set("response", new CborByteString(response));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.StartsWith("SafetyNet response security token validation failed", ex.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseClaimTimestampExpired()
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
                    { COSE.KeyTypeParameter.Crv, curve }
                };

                var x = (byte[])cpk[COSE.KeyTypeParameter.X];
                var y = (byte[])cpk[COSE.KeyTypeParameter.Y];

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

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(strToken) }
                });
            }
        }
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.StartsWith("SafetyNet timestampMs must be between one minute ago and now, got:", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseClaimTimestampNotYetValid()
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

                using (X509Certificate2 publicOnly = attRequest.Create( root, notBefore, notAfter, serial))
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
                var y =  (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                var claims = new List<Claim>
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

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(strToken) }
                });
            }
        }
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.StartsWith("SafetyNet timestampMs must be between one minute ago and now, got:", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseClaimTimestampMissing()
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

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(strToken) }
                });
            }
        }
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("SafetyNet timestampMs not found SafetyNet attestation", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseClaimNonceMissing()
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

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(strToken) }
                });
            }
        }
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Nonce value not found in SafetyNet attestation", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseClaimNonceInvalid()
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

                using (X509Certificate2 publicOnly = attRequest.Create(
                    root,
                    notBefore,
                    notAfter,
                    serial))
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

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(strToken) }
                });
            }
        }
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.StartsWith("SafetyNet response nonce / hash value mismatch", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetResponseClaimNonceNotBase64String()
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

                using (X509Certificate2 publicOnly = attRequest.Create(
                    root,
                    notBefore,
                    notAfter,
                    serial))
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

                var claims = new List<Claim> {
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

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(strToken) }
                });
            }
        }
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("Nonce value not base64string in SafetyNet attestation", ex.Result.Message);
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

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(strToken) }
                });
            }
        }
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.StartsWith("Invalid SafetyNet attestation cert DnsName", ex.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetCtsProfileMatchMissing()
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

                using (X509Certificate2 publicOnly = attRequest.Create(
                    root,
                    notBefore,
                    notAfter,
                    serial))
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

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(strToken) }
                });
            }
        }
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("SafetyNet response ctsProfileMatch missing", ex.Result.Message);
    }

    [Fact]
    public void TestAndroidSafetyNetCtsProfileMatchFalse()
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
                var y =  (byte[])cpk[COSE.KeyTypeParameter.Y];

                _credentialPublicKey = new CredentialPublicKey(cpk);

                var attToBeSigned = _attToBeSignedHash(HashAlgorithmName.SHA256);

                var claims = new List<Claim>
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

                _attestationObject.Set("attStmt", new CborMap {
                    { "ver", "F1D0" },
                    { "response", Encoding.UTF8.GetBytes(strToken) }
                 });
            }
        }
        var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
        Assert.Equal("SafetyNet response ctsProfileMatch false", ex.Result.Message);
    }
}
