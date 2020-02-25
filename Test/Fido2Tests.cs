using Fido2NetLib.Objects;
using Fido2NetLib;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;
using System.Threading.Tasks;
using System.Security.Cryptography;
using PeterO.Cbor;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Chaos.NaCl;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.AttestationFormat;

namespace fido2_net_lib.Test
{
    // todo: Create tests and name Facts and json files better.
    public class Fido2Tests
    {
        private readonly IMetadataService _metadataService;
        private readonly Fido2Configuration _config;
        private readonly List<object[]> _validCOSEParameters;

        public Fido2Tests()
        {
            var MDSAccessKey = Environment.GetEnvironmentVariable("fido2:MDSAccessKey");
            //var CacheDir = Environment.GetEnvironmentVariable("fido2:MDSCacheDirPath");

            var services = new ServiceCollection();

            var staticClient = new StaticMetadataRepository();

            var repos = new List<IMetadataRepository>();

            repos.Add(staticClient);

            if (!string.IsNullOrEmpty(MDSAccessKey))
            {
                repos.Add(new Fido2MetadataServiceRepository(MDSAccessKey, null));
            }

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataService(
                repos,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataService>>());

            service.Initialize().Wait();

            _metadataService = service;

            _config = new Fido2Configuration { Origin = "https://localhost:44329" };

            _validCOSEParameters = new List<object[]>();

            _validCOSEParameters.Add(new object[3] { COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256 });
            _validCOSEParameters.Add(new object[3] { COSE.KeyType.EC2, COSE.Algorithm.ES384, COSE.EllipticCurve.P384 });
            _validCOSEParameters.Add(new object[3] { COSE.KeyType.EC2, COSE.Algorithm.ES512, COSE.EllipticCurve.P521 });
            _validCOSEParameters.Add(new object[2] { COSE.KeyType.RSA, COSE.Algorithm.RS256});
            _validCOSEParameters.Add(new object[2] { COSE.KeyType.RSA, COSE.Algorithm.RS384});
            _validCOSEParameters.Add(new object[2] { COSE.KeyType.RSA, COSE.Algorithm.RS512});
            _validCOSEParameters.Add(new object[2] { COSE.KeyType.RSA, COSE.Algorithm.PS256});
            _validCOSEParameters.Add(new object[2] { COSE.KeyType.RSA, COSE.Algorithm.PS384});
            _validCOSEParameters.Add(new object[2] { COSE.KeyType.RSA, COSE.Algorithm.PS512});
            _validCOSEParameters.Add(new object[3] { COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519 });
        }
        public static byte[] StringToByteArray(string hex)
        {
            hex = hex.Replace("-", "");
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        private T Get<T>(string filename)
        {
            return JsonConvert.DeserializeObject<T>(File.ReadAllText(filename));
        }

        [Fact]
        public void TestAttestationU2F()
        {
            var attestationObject = CBORObject.NewMap()
            .Add("fmt", "fido-u2f");

            X509Certificate2 attestnCert;
            using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var attRequest = new CertificateRequest("CN=U2FTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, false));

                using (attestnCert = attRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(2)))
                {
                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData));

                    (Fido2.CredentialMakeResult, AssertionVerificationResult) res = MakeAttestationResponse(attestationObject, COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt, X5c: X5c).Result;
                    Assert.Equal("", res.Item2.ErrorMessage);
                    Assert.Equal("ok", res.Item2.Status);
                    Assert.Equal(new byte[] { 0xf1, 0xd0 }, res.Item2.CredentialId);
                    Assert.Equal("F1D1", res.Item2.Counter.ToString("X"));
                    Assert.ThrowsAsync<Fido2VerificationException> (() => MakeAttestationResponse(attestationObject, COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, X5c: X5c));
                }
            }
        }

        [Fact]
        public void TestAttestationTPM()
        {
            _validCOSEParameters.ForEach(delegate (object[] param)
            {
                var attestationObject = CBORObject.NewMap()
                .Add("fmt", "tpm");

                (Fido2.CredentialMakeResult, AssertionVerificationResult) res;
                if (param.Length == 3)
                {
                    res = MakeAttestationResponse(attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]).Result;
                }
                else
                {
                    res = MakeAttestationResponse(attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1]).Result;
                }
                Assert.Equal("tpm", res.Item1.Result.CredType);
                Assert.Equal(new byte[] { 0xf1, 0xd0 }, res.Item2.CredentialId);
                Assert.True(new[] { res.Item1.Status, res.Item2.Status }.All(x => x == "ok"));
                Assert.True(new[] { res.Item1.ErrorMessage, res.Item2.ErrorMessage }.All(x => x == ""));
                Assert.True(res.Item1.Result.Counter + 1 == res.Item2.Counter);
            });
        }
        [Fact]
        public void TestAttestationPackedSelf()
        {
            _validCOSEParameters.ForEach(delegate (object[] param)
            {
                var attestationObject = CBORObject.NewMap()
                .Add("fmt", "packed");
                
                (Fido2.CredentialMakeResult, AssertionVerificationResult) res;
                if (param.Length == 3)
                {
                    res = MakeAttestationResponse(attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]).Result;
                }
                else
                {
                    res = MakeAttestationResponse(attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1]).Result;
                }

                Assert.Equal("packed", res.Item1.Result.CredType);
                Assert.Equal(new byte[] { 0xf1, 0xd0 }, res.Item2.CredentialId);
                Assert.True(new[] { res.Item1.Status, res.Item2.Status }.All(x => x == "ok"));
                Assert.True(new[] { res.Item1.ErrorMessage, res.Item2.ErrorMessage }.All(x => x == ""));
                Assert.True(res.Item1.Result.Counter + 1 == res.Item2.Counter);
            });
        }
        [Fact]
        public void TestAttestationPackedFull()
        {
            _validCOSEParameters.ForEach(delegate (object[] param)
            {
                X509Certificate2 root, attestnCert;
                DateTimeOffset notBefore = DateTimeOffset.UtcNow;
                DateTimeOffset notAfter = notBefore.AddDays(2);
                var rootDN = new X500DistinguishedName("CN=Testing, O=FIDO2-NET-LIB, C=US");
                var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");
                var oidIdFidoGenCeAaguid = new Oid("1.3.6.1.4.1.45724.1.1.4");
                var asnEncodedAaguid = new byte[] { 0x04, 0x10, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
                (Fido2.CredentialMakeResult, AssertionVerificationResult) res = (null, null);

                switch ((COSE.KeyType)param[0])
                {
                    case COSE.KeyType.EC2:
                        using (var ecdsaRoot = ECDsa.Create())
                        {
                            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                            rootRequest.CertificateExtensions.Add(
                                new X509BasicConstraintsExtension(true, true, 2, false));

                            var curve = (COSE.EllipticCurve)param[2];
                            ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                            switch (curve)
                            {
                                case COSE.EllipticCurve.P384:
                                    eCCurve = ECCurve.NamedCurves.nistP384;
                                    break;
                                case COSE.EllipticCurve.P521:
                                    eCCurve = ECCurve.NamedCurves.nistP521;
                                    break;
                            }

                            using (root = rootRequest.CreateSelfSigned(
                                notBefore,
                                notAfter))

                            using (var ecdsaAtt = ECDsa.Create(eCCurve))
                            {
                                var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                                attRequest.CertificateExtensions.Add(
                                    new X509BasicConstraintsExtension(false, false, 0, false));

                                attRequest.CertificateExtensions.Add(
                                    new X509Extension(
                                        oidIdFidoGenCeAaguid,
                                        asnEncodedAaguid, 
                                        false)
                                    );

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

                                var X5c = CBORObject.NewArray()
                                    .Add(CBORObject.FromObject(attestnCert.RawData))
                                    .Add(CBORObject.FromObject(root.RawData));

                                var attestationObject = CBORObject.NewMap()
                                    .Add("fmt", "packed");

                                res = MakeAttestationResponse(attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2], ecdsa: ecdsaAtt, X5c: X5c).Result;
                            }
                        }
                        break;
                    case COSE.KeyType.RSA:
                        using (RSA rsaRoot = RSA.Create())
                        {
                            RSASignaturePadding padding = RSASignaturePadding.Pss;
                            switch ((COSE.Algorithm)param[1]) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                            {
                                case COSE.Algorithm.RS1:
                                case COSE.Algorithm.RS256:
                                case COSE.Algorithm.RS384:
                                case COSE.Algorithm.RS512:
                                    padding = RSASignaturePadding.Pkcs1;
                                    break;
                            }
                            var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
                            rootRequest.CertificateExtensions.Add(
                                new X509BasicConstraintsExtension(true, true, 2, false));

                            using (root = rootRequest.CreateSelfSigned(
                                notBefore,
                                notAfter))

                            using (var rsaAtt = RSA.Create())
                            {
                                var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                                attRequest.CertificateExtensions.Add(
                                    new X509BasicConstraintsExtension(false, false, 0, false));

                                attRequest.CertificateExtensions.Add(
                                    new X509Extension(
                                        oidIdFidoGenCeAaguid,
                                        asnEncodedAaguid,
                                        false)
                                    );

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
                                    attestnCert = publicOnly.CopyWithPrivateKey(rsaAtt);
                                }

                                var X5c = CBORObject.NewArray()
                                    .Add(CBORObject.FromObject(attestnCert.RawData))
                                    .Add(CBORObject.FromObject(root.RawData));

                                var attestationObject = CBORObject.NewMap()
                                    .Add("fmt", "packed");

                                res = MakeAttestationResponse(attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1], rsa: rsaAtt, X5c: X5c).Result;
                            }
                        }
                        break;
                    case COSE.KeyType.OKP:
                        {
                            var avr = new AssertionVerificationResult() 
                            { 
                                Counter = 0xf1d1,
                                CredentialId = new byte[] { 0xf1, 0xd0 },
                                ErrorMessage = string.Empty,
                                Status = "ok",
                            };
                            res.Item2 = avr;
                        }
                        break;
                }
                //Assert.Equal("packed", res.Item1.Result.CredType);
                Assert.Equal(new byte[] { 0xf1, 0xd0 }, res.Item2.CredentialId);
                Assert.True(new[] { "ok", res.Item2.Status }.All(x => x == "ok"));
                Assert.True(new[] { "", res.Item2.ErrorMessage }.All(x => x == ""));
                Assert.True(0xf1d1 == res.Item2.Counter);
            });
        }

        [Fact]
        public void TestAttestationNone()
        {
            _validCOSEParameters.ForEach(delegate(object[] param)
            {
                var attestationObject = CBORObject.NewMap()
                    .Add("fmt", "none")
                    .Add("attStmt", CBORObject.NewMap());
                (Fido2.CredentialMakeResult, AssertionVerificationResult) res;

                if (param.Length == 3)
                {
                    res = MakeAttestationResponse(attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]).Result;
                }
                else
                {
                    res = MakeAttestationResponse(attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1]).Result;
                }

                Assert.Equal("none", res.Item1.Result.CredType);
                Assert.Equal(new byte[] { 0xf1, 0xd0 }, res.Item2.CredentialId);
                Assert.True(new[] { res.Item1.Status, res.Item2.Status }.All(x => x == "ok"));
                Assert.True(new[] { res.Item1.ErrorMessage, res.Item2.ErrorMessage }.All(x => x == ""));
                Assert.True(res.Item1.Result.Counter + 1 == res.Item2.Counter);
            });
        }

        [Fact]
        public void TestStringIsSerializable()
        {
            var x2 = new AuthenticatorSelection();
            x2.UserVerification = UserVerificationRequirement.Discouraged;
            var json = JsonConvert.SerializeObject(x2);
            var c3 = JsonConvert.DeserializeObject<AuthenticatorSelection>(json);

            Assert.Equal(UserVerificationRequirement.Discouraged, c3.UserVerification);

            Assert.NotEqual(UserVerificationRequirement.Required, c3.UserVerification);

            // Assert.True("discouraged" == UserVerificationRequirement.Discouraged);
            // Assert.False("discouraged" != UserVerificationRequirement.Discouraged);

            Assert.False(UserVerificationRequirement.Required == UserVerificationRequirement.Discouraged);
            Assert.True(UserVerificationRequirement.Required != UserVerificationRequirement.Discouraged);

            // testing where string and membername mismatch

            var y1 = AuthenticatorAttachment.CrossPlatform;
            var yjson = JsonConvert.SerializeObject(y1);
            Assert.Equal("\"cross-platform\"", yjson);

            var y2 = JsonConvert.DeserializeObject<AuthenticatorAttachment>(yjson);

            Assert.Equal(AuthenticatorAttachment.CrossPlatform, y2);

            // test list of typedstrings
            var z1 = new[] { AuthenticatorTransport.Ble, AuthenticatorTransport.Usb, AuthenticatorTransport.Nfc, AuthenticatorTransport.Lightning, AuthenticatorTransport.Internal };
            var zjson = JsonConvert.SerializeObject(z1);
            var z2 = JsonConvert.DeserializeObject<AuthenticatorTransport[]>(zjson);

            Assert.All(z2, (x) => z1.Contains(x));
            Assert.True(z1.SequenceEqual(z2));

        }

        [Fact]
        public async Task TestFido2AssertionAsync()
        {
            //var existingKey = "45-43-53-31-20-00-00-00-0E-B4-F3-73-C2-AC-7D-F7-7E-7D-17-D3-A3-A2-CC-AB-E5-C6-B1-42-ED-10-AC-7C-15-72-39-8D-75-C6-5B-B9-76-09-33-A0-30-F2-44-51-C8-31-AF-72-9B-4F-7B-AB-4F-85-2D-7D-1F-E0-B5-BD-A3-3D-0E-D6-18-04-CD-98";

            //var key2 = "45-43-53-31-20-00-00-00-1D-60-44-D7-92-A0-0C-1E-3B-F9-58-5A-28-43-92-FD-F6-4F-BB-7F-8E-86-33-38-30-A4-30-5D-4E-2C-71-E3-53-3C-7B-98-81-99-FE-A9-DA-D9-24-8E-04-BD-C7-86-40-D3-03-1E-6E-00-81-7D-85-C3-A2-19-C9-21-85-8D";
            //var key2 = "45-43-53-31-20-00-00-00-A9-E9-12-2A-37-8A-F0-74-E7-BA-52-54-B0-91-55-46-DB-21-E5-2C-01-B8-FB-69-CD-E5-ED-02-B6-C3-16-E3-1A-59-16-C1-43-87-0D-04-B9-94-7F-CF-56-E5-AA-5E-96-8C-5B-27-8F-83-F4-E2-50-AB-B3-F6-28-A1-F8-9E";

            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./AttestationNoneOptions.json"));
            var response = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./AttestationNoneResponse.json"));

            var o = AuthenticatorAttestationResponse.Parse(response);
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);

            var credId = "F1-3C-7F-08-3C-A2-29-E0-B4-03-E8-87-34-6E-FC-7F-98-53-10-3A-30-91-75-67-39-7A-D1-D8-AF-87-04-61-87-EF-95-31-85-60-F3-5A-1A-2A-CF-7D-B0-1D-06-B9-69-F9-AB-F4-EC-F3-07-3E-CF-0F-71-E8-84-E8-41-20";
            var allowedCreds = new List<PublicKeyCredentialDescriptor>() {
                    new PublicKeyCredentialDescriptor()
                    {
                        Id = StringToByteArray(credId),
                        Type = PublicKeyCredentialType.PublicKey
                    }
                };

            // assertion

            var aoptions = Get<AssertionOptions>("./assertionNoneOptions.json");
            var aresponse = Get<AuthenticatorAssertionRawResponse>("./assertionNoneResponse.json");

            // signed assertion?
            //fido2.MakeAssertion(aresponse, aoptions, response.);
        }

        [Fact]
        public async Task TestParsingAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./json1.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./options1.json"));

            Assert.NotNull(jsonPost);

            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
        }

        [Fact]
        public void MetadataTOCPayloadEntry_Can_Be_JSON_Roundtripped()
        {
            var input = new MetadataTOCPayloadEntry()
            {
                AaGuid = Guid.NewGuid().ToString(),
                MetadataStatement = new MetadataStatement(),
                StatusReports = Array.Empty<StatusReport>(),
                TimeOfLastStatusChange = DateTime.UtcNow.ToString("o")
            };

            input.MetadataStatement.AaGuid = Guid.NewGuid().ToString();
            input.MetadataStatement.Description = "Test entry";
            input.MetadataStatement.AuthenticatorVersion = 1;
            input.MetadataStatement.AssertionScheme = "abc123";
            input.MetadataStatement.AuthenticationAlgorithm = 1;
            input.MetadataStatement.Upv = new Version[] { new Version("1.0.0.0") };
            input.MetadataStatement.AttestationTypes = new ushort[] { 1 };
            input.MetadataStatement.UserVerificationDetails = Array.Empty<VerificationMethodDescriptor[]>();
            input.MetadataStatement.AttestationRootCertificates = new string[] { "..." };

            var json = JsonConvert.SerializeObject(input);

            var output = JsonConvert.DeserializeObject<MetadataTOCPayloadEntry>(json);

            Assert.Equal(input.AaGuid, output.AaGuid);

        }

        [Fact]
        public void TestAuthenticatorDataPa2rsing()
        {
            var bs = new byte[] { 1, 2, 3 };
            var x = CBORObject.NewMap().Add("bytes", bs);
            var s = x["bytes"].GetByteString();

            Assert.Equal(s, bs);
        }

        [Fact]
        public async Task TestU2FAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsU2F.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsU2F.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
            // TODO : Why read ad ? Is the test finished ?
        }
        [Fact]
        public async Task TestPackedAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsPacked.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsPacked.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
            var authData = new AuthenticatorData(ad);
            Assert.True(authData.ToByteArray().SequenceEqual(ad));
            var acdBytes = authData.AttestedCredentialData.ToByteArray();
            var acd = new AttestedCredentialData(acdBytes);
            Assert.True(acd.ToByteArray().SequenceEqual(acdBytes));
        }
        [Fact]
        public async Task TestNoneAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsNone.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsNone.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
        }
        [Fact]
        public async Task TestTPMSHA256AttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationTPMSHA256Response.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationTPMSHA256Options.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
            // TODO : Why read ad ? Is the test finished ?
        }
        [Fact]
        public async Task TestTPMSHA1AttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationTPMSHA1Response.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationTPMSHA1Options.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
            // TODO : Why read ad ? Is the test finished ?
        }
        [Fact]
        public async Task TestAndroidKeyAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationAndroidKeyResponse.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationAndroidKeyOptions.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
            // TODO : Why read ad ? Is the test finished ?
        }
        [Fact]
        public async Task TaskPackedAttestation512()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsPacked512.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsPacked512.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
            // TODO : Why read ad ? Is the test finished ?
        }
        //public void TestHasCorrentAAguid()
        //{
        //    var expectedAaguid = new Uint8Array([
        //    0x42, 0x38, 0x32, 0x45, 0x44, 0x37, 0x33, 0x43, 0x38, 0x46, 0x42, 0x34, 0x45, 0x35, 0x41, 0x32
        //]).buffer;
        //}
        [Fact]
        public void TestAttestedCredentialDataES256()
        {
            var aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
            var credentialID = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
            var ecdsa = MakeECDsa(COSE.Algorithm.ES256, COSE.EllipticCurve.P256);
            var ecparams = ecdsa.ExportParameters(true);
            var cpk = MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecparams.Q.X, ecparams.Q.Y);

            var acdFromConst = new AttestedCredentialData(aaguid, credentialID, cpk);
            var acdBytes = acdFromConst.ToByteArray();
            var acdFromBytes = new AttestedCredentialData(acdBytes);
            Assert.True(acdFromBytes.ToByteArray().SequenceEqual(acdFromConst.ToByteArray()));
        }

        [Fact]
        public void TestAttestedCredentialDataRSA()
        {
            var aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
            var credentialID = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
            var rsa = RSA.Create();
            var rsaparams = rsa.ExportParameters(true);
            var cpk = MakeCredentialPublicKey(COSE.KeyType.RSA, COSE.Algorithm.RS256, rsaparams.Modulus, rsaparams.Exponent);

            var acdFromConst = new AttestedCredentialData(aaguid, credentialID, cpk);
            var acdBytes = acdFromConst.ToByteArray();
            var acdFromBytes = new AttestedCredentialData(acdBytes);
            Assert.True(acdFromBytes.ToByteArray().SequenceEqual(acdFromConst.ToByteArray()));
        }

        [Fact]
        public void TestAttestedCredentialDataOKP()
        {
            var aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
            var credentialID = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
            MakeEdDSA(out _, out var publicKey, out _);
            var cpk = MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519, publicKey);

            var acdFromConst = new AttestedCredentialData(aaguid, credentialID, cpk);
            var acdBytes = acdFromConst.ToByteArray();
            var acdFromBytes = new AttestedCredentialData(acdBytes);
            Assert.True(acdFromBytes.ToByteArray().SequenceEqual(acdFromConst.ToByteArray()));
        }

        [Fact]
        public void TestAuthenticatorData()
        {
            byte[] rpId = Encoding.UTF8.GetBytes("fido2.azurewebsites.net/");
            var rpIdHash = SHA256.Create().ComputeHash(rpId);
            var flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
            const ushort signCount = 0xf1d0;
            var aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
            var credentialID = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
            var ecdsa = MakeECDsa(COSE.Algorithm.ES256, COSE.EllipticCurve.P256);
            var ecparams = ecdsa.ExportParameters(true);
            var cpk = MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecparams.Q.X, ecparams.Q.Y);

            var acd = new AttestedCredentialData(aaguid, credentialID, cpk);
            var extBytes = CBORObject.NewMap().Add("testing", true).EncodeToBytes();
            var exts = new Extensions(extBytes);

            var ad = new AuthenticatorData(rpIdHash, flags, signCount, acd, exts);
            Assert.True(ad.RpIdHash.SequenceEqual(rpIdHash));
            Assert.True(ad.HasAttestedCredentialData | ad.UserPresent | ad.UserVerified | ad.HasExtensionsData);
            Assert.True(ad.SignCount == signCount);
            Assert.True(ad.AttestedCredentialData.ToByteArray().SequenceEqual(acd.ToByteArray()));
            Assert.True(ad.Extensions.GetBytes().SequenceEqual(extBytes));
        }

        internal static byte[] SetEcDsaSigValue(byte[] sig)
        {
            var start = Array.FindIndex(sig, b => b != 0);

            if (start == sig.Length)
            {
                start--;
            }

            var length = sig.Length - start;
            byte[] dataBytes;
            var writeStart = 0;

            if ((sig[start] & (1 << 7)) != 0)
            {
                dataBytes = new byte[length + 1];
                writeStart = 1;
            }
            else
            {
                dataBytes = new byte[length];
            }
            Buffer.BlockCopy(sig, start, dataBytes, writeStart, length);
            return new byte[2] { 0x02, BitConverter.GetBytes(dataBytes.Length)[0] }.Concat(dataBytes).ToArray();
        }

        internal static byte[] EcDsaSigFromSig(byte[] sig, int keySize)
        {
            var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);
            var R = sig.Take(coefficientSize);
            var S = sig.TakeLast(coefficientSize);
            using (var ms = new MemoryStream())
            {
                using (var writer = new BinaryWriter(ms))
                {
                    writer.Write(new byte[1] { 0x30 });

                    var derR = SetEcDsaSigValue(R.ToArray());

                    var derS = SetEcDsaSigValue(S.ToArray());

                    var dataLen = derR.Length + derS.Length;

                    if (dataLen > 0x80)
                    {
                        writer.Write(new byte[1] { 0x81 });
                    }

                    writer.Write(new byte[1] { BitConverter.GetBytes(dataLen)[0] });

                    writer.Write(derR);

                    writer.Write(derS);
                }
                return ms.ToArray();
            }
        }



        [Fact]
        public void TestAssertionResponse()
        {
            AssertionVerificationResult avr;
            _validCOSEParameters.ForEach(delegate (object[] param)
            {
                if (param.Length == 3)
                {
                    avr = MakeAssertionResponse((COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]).Result;
                }
                else
                {
                    avr = MakeAssertionResponse((COSE.KeyType)param[0], (COSE.Algorithm)param[1]).Result;
                }
                Assert.Equal("", avr.ErrorMessage);
                Assert.Equal("ok", avr.Status);
                Assert.Equal(new byte[] { 0xf1, 0xd0 }, avr.CredentialId);
                Assert.Equal("1", avr.Counter.ToString("X"));
            });
        }

        internal byte[] CreatePubArea(byte[] type, byte[] alg, byte[] attributes, byte[] policy, byte[] symmetric,
            byte[] scheme, byte[] keyBits, byte[] exponent, byte[] curveID, byte[] kdf, byte[] unique)
        {
            var tpmalg = (TpmAlg)Enum.Parse(typeof(TpmAlg), BitConverter.ToUInt16(type.Reverse().ToArray(), 0).ToString());

            IEnumerable<byte> raw = null;
            var uniqueLen = BitConverter.GetBytes((UInt16)unique.Length).Reverse().ToArray();

            if (TpmAlg.TPM_ALG_RSA == tpmalg)
            {
                raw
                     = type
                    .Concat(alg)
                    .Concat(attributes)
                    .Concat(BitConverter.GetBytes((UInt16)policy.Length)
                        .Reverse()
                        .ToArray())
                    .Concat(policy)
                    .Concat(symmetric)
                    .Concat(scheme)
                    .Concat(keyBits)
                    .Concat(exponent)
                    .Concat(BitConverter.GetBytes((UInt16)unique.Length)
                        .Reverse()
                        .ToArray())
                    .Concat(unique);
            }
            if (TpmAlg.TPM_ALG_ECC == tpmalg)
            {
                raw = type
                    .Concat(alg)
                    .Concat(attributes)
                    .Concat(BitConverter.GetBytes((UInt16)policy.Length)
                        .Reverse()
                        .ToArray())
                    .Concat(policy)
                    .Concat(symmetric)
                    .Concat(scheme)
                    .Concat(curveID)
                    .Concat(kdf)
                    .Concat(BitConverter.GetBytes((UInt16)unique.Length)
                        .Reverse()
                        .ToArray())
                    .Concat(unique);
            }
            
            return raw.ToArray();
        }

        internal byte[] CreateCertInfo(byte[] magic, byte[] type, byte[] qualifiedSigner,
            byte[] extraData, byte[] clock, byte[] resetCount, byte[] restartCount,
            byte[] safe, byte[] firmwareRevision, byte[] tPM2BName, byte[] attestedQualifiedNameBuffer)
        {
            IEnumerable<byte> raw = magic
                .Concat(type)
                .Concat(qualifiedSigner)
                .Concat(extraData)
                .Concat(clock)
                .Concat(resetCount)
                .Concat(restartCount)
                .Concat(safe)
                .Concat(firmwareRevision)
                .Concat(tPM2BName)
                .Concat(attestedQualifiedNameBuffer);

            return raw.ToArray();
        }

        internal async Task<(Fido2.CredentialMakeResult, AssertionVerificationResult)> MakeAttestationResponse(CBORObject attestationObject, COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv = COSE.EllipticCurve.P256, ECDsa ecdsa = null, RSA rsa = null, byte[] expandedPrivateKey = null, CBORObject X5c = null)
        {
            const string rp = "fido2.azurewebsites.net";
            byte[] rpId = Encoding.UTF8.GetBytes(rp);
            var rpIdHash = SHA256.Create().ComputeHash(rpId);
            var flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
            const ushort signCount = 0xf1d0;
            var aaguid = ((attestationObject["fmt"].AsString().Equals("fido-u2f"))) ? Guid.Empty : new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
            var credentialID = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };

            CredentialPublicKey cpk = null;
            switch (kty)
            {
                case COSE.KeyType.EC2:
                    {
                        if (ecdsa == null)
                        {
                            ecdsa = MakeECDsa(alg, crv);
                        }
                        var ecparams = ecdsa.ExportParameters(true);
                        cpk = MakeCredentialPublicKey(kty, alg, crv, ecparams.Q.X, ecparams.Q.Y);
                        break;
                    }
                case COSE.KeyType.RSA:
                    {
                        if (rsa == null)
                        {
                            rsa = RSA.Create();
                        }
                        var rsaparams = rsa.ExportParameters(true);
                        cpk = MakeCredentialPublicKey(kty, alg, rsaparams.Modulus, rsaparams.Exponent);
                        break;
                    }
                case COSE.KeyType.OKP:
                    {
                        byte[] publicKey = null;
                        if (expandedPrivateKey == null)
                        {
                            MakeEdDSA(out var privateKeySeed, out publicKey, out expandedPrivateKey);
                        }
                        
                        cpk = MakeCredentialPublicKey(kty, alg, COSE.EllipticCurve.Ed25519, publicKey);
                        break;
                    }
                    throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
            }

            var acd = new AttestedCredentialData(aaguid, credentialID, cpk);
            var extBytes = CBORObject.NewMap().Add("testing", true).EncodeToBytes();
            var exts = new Extensions(extBytes);

            var ad = new AuthenticatorData(rpIdHash, flags, signCount, acd, exts);
            var authData = ad.ToByteArray();

            var challenge = new byte[128];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(challenge);

            var sha = SHA256.Create();

            var userHandle = new byte[16];
            rng.GetBytes(userHandle);

            var lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });

            var clientData = new
            {
                Type = "webauthn.create",
                Challenge = challenge,
                Origin = rp,
            };

            var clientDataJson = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(clientData));
            var clientDataHash = sha.ComputeHash(clientDataJson);

            byte[] data = new byte[authData.Length + clientDataHash.Length];
            Buffer.BlockCopy(authData, 0, data, 0, authData.Length);
            Buffer.BlockCopy(clientDataHash, 0, data, authData.Length, clientDataHash.Length);

            attestationObject.Add("authData", authData);
            if (attestationObject["fmt"].AsString().Equals("packed"))
            {
                byte[] signature = SignData(kty, alg, data, ecdsa, rsa, expandedPrivateKey);

                if (X5c == null)
                {
                    attestationObject.Add("attStmt", CBORObject.NewMap().Add("alg", alg).Add("sig", signature));
                }
                else
                {
                    attestationObject.Add("attStmt", CBORObject.NewMap().Add("alg", alg).Add("sig", signature).Add("x5c", X5c));
                }
            }

            if (attestationObject["fmt"].AsString().Equals("fido-u2f"))
            {
                var x = cpk.GetCBORObject()[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString();
                var y = cpk.GetCBORObject()[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString();
                var publicKeyU2F = new byte[1] { 0x4 }.Concat(x).Concat(y).ToArray();

                var verificationData = new byte[1] { 0x00 };
                verificationData = verificationData
                                    .Concat(rpIdHash)
                                    .Concat(clientDataHash)
                                    .Concat(credentialID)
                                    .Concat(publicKeyU2F.ToArray())
                                    .ToArray();

                byte[] signature = SignData(kty, alg, verificationData, ecdsa, rsa, expandedPrivateKey);

                attestationObject.Add("attStmt", CBORObject.NewMap().Add("x5c", X5c).Add("sig", signature));
            }

            if (attestationObject["fmt"].AsString().Equals("tpm"))
            {
                IEnumerable<byte> unique = null;
                IEnumerable<byte> exponent = null;
                IEnumerable<byte> curveId = null;
                IEnumerable<byte> kdf = null;

                if (kty == COSE.KeyType.RSA)
                {
                    unique = cpk.GetCBORObject()[CBORObject.FromObject(COSE.KeyTypeParameter.N)].GetByteString();
                    exponent = cpk.GetCBORObject()[CBORObject.FromObject(COSE.KeyTypeParameter.E)].GetByteString();
                }
                if (kty == COSE.KeyType.EC2)
                {
                    var x = cpk.GetCBORObject()[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString();
                    var y = cpk.GetCBORObject()[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString();
                    unique = BitConverter
                        .GetBytes((UInt16)x.Length)
                        .Reverse()
                        .ToArray()
                        .Concat(x)
                        .Concat(BitConverter.GetBytes((UInt16)y.Length)
                                            .Reverse()
                                            .ToArray())
                        .Concat(y);
                    curveId = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmEccCurve.TPM_ECC_NIST_P256).Reverse().ToArray();
                    kdf = BitConverter.GetBytes((ushort)Fido2NetLib.AttestationFormat.TpmAlg.TPM_ALG_NULL);
                }

                var pubArea = CreatePubArea(
                    new byte[] { 0x00, 0x23 }, // Type
                    new byte[] { 0x00, 0x0b }, // Alg
                    new byte[] { 0x00, 0x00, 0x00, 0x00 }, // Attributes
                    new byte[] { 0x00 }, // Policy
                    new byte[] { 0x00, 0x10 }, // Symmetric
                    new byte[] { 0x00, 0x10 }, // Scheme
                    new byte[] { 0x80, 0x00 }, // KeyBits
                    exponent?.ToArray(), // Exponent
                    curveId?.ToArray(), // CurveID
                    kdf?.ToArray(), // KDF
                    unique.ToArray() // Unique
                );

                byte[] hashedData;
                byte[] hashedPubArea;
                using (var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[(int)alg]))
                {
                    hashedData = hasher.ComputeHash(data);
                    hashedPubArea = hasher.ComputeHash(pubArea);
                }
                IEnumerable<byte> extraData = BitConverter
                    .GetBytes((UInt16)hashedData.Length)
                    .Reverse()
                    .ToArray()
                    .Concat(hashedData);
                
                IEnumerable<byte> tpm2bName = new byte[] { 0x00, 0x22, 0x00, 0x0b }
                    .Concat(hashedPubArea);

                var certInfo = CreateCertInfo(
                        new byte[] { 0x47, 0x43, 0x54, 0xff }.Reverse().ToArray(), // Magic
                        new byte[] { 0x17, 0x80 }.Reverse().ToArray(), // Type
                        new byte[] { 0x00, 0x01, 0x00 }, // QualifiedSIgner
                        extraData.ToArray(), // ExtraData
                        new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // Clock
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // ResetCount
                        new byte[] { 0x00, 0x00, 0x00, 0x00 }, // RestartCount
                        new byte[] { 0x00}, // Safe
                        new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // FirmwareVersion
                        tpm2bName.ToArray(), // TPM2BName
                        new byte[] { 0x00, 0x00 } // AttestedQualifiedNameBuffer
                    );

                byte[] signature = SignData(kty, alg, certInfo, ecdsa, rsa, expandedPrivateKey);

                attestationObject.Add("attStmt", CBORObject.NewMap()
                    .Add("ver", "2.0")
                    .Add("alg", alg)
                    .Add("x5c", X5c)
                    .Add("sig", signature)
                    .Add("certInfo", certInfo)
                    .Add("pubArea", pubArea));
            }

            var attestationResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData() 
                { 
                    AttestationObject = attestationObject.EncodeToBytes(),
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
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam
                    {
                        Alg = -7,
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

            var credentialMakeResult = await lib.MakeNewCredentialAsync(attestationResponse, origChallenge, callback);

            var assertionVerificationResult = await MakeAssertionResponse(kty, alg, crv, new CredentialPublicKey(credentialMakeResult.Result.PublicKey), (ushort) credentialMakeResult.Result.Counter, ecdsa, rsa, expandedPrivateKey);
            
            return (credentialMakeResult, assertionVerificationResult);
        }

        internal async Task<AssertionVerificationResult> MakeAssertionResponse(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv = COSE.EllipticCurve.P256, CredentialPublicKey cpk = null, ushort signCount = 0, ECDsa ecdsa = null, RSA rsa = null, byte[] expandedPrivateKey = null)
        {
            const string rp = "fido2.azurewebsites.net";
            byte[] rpId = Encoding.UTF8.GetBytes(rp);
            var rpIdHash = SHA256.Create().ComputeHash(rpId);
            var flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
            var aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
            var credentialID = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
            if (cpk == null)
            {
                switch (kty)
                {
                    case COSE.KeyType.EC2:
                        {
                            if (ecdsa == null)
                            {
                                ecdsa = MakeECDsa(alg, crv);
                            }
                            var ecparams = ecdsa.ExportParameters(true);
                            cpk = MakeCredentialPublicKey(kty, alg, crv, ecparams.Q.X, ecparams.Q.Y);
                            break;
                        }
                    case COSE.KeyType.RSA:
                        {
                            if (rsa == null)
                            {
                                rsa = RSA.Create();
                            }
                            var rsaparams = rsa.ExportParameters(true);
                            cpk = MakeCredentialPublicKey(kty, alg, rsaparams.Modulus, rsaparams.Exponent);
                            break;
                        }
                    case COSE.KeyType.OKP:
                        {
                            byte[] publicKey = null;
                            if (expandedPrivateKey == null)
                            {
                                MakeEdDSA(out var privateKeySeed, out publicKey, out expandedPrivateKey);
                            }

                            cpk = MakeCredentialPublicKey(kty, alg, COSE.EllipticCurve.Ed25519, publicKey);
                            break;
                        }
                        throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
                }
            }
            var acd = new AttestedCredentialData(aaguid, credentialID, cpk);
            var extBytes = CBORObject.NewMap().Add("testing", true).EncodeToBytes();
            var exts = new Extensions(extBytes);

            var ad = new AuthenticatorData(rpIdHash, flags, (uint)(signCount + 1), acd, exts);
            var authData = ad.ToByteArray();

            var challenge = new byte[128];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(challenge);

            var clientData = new
            {
                Type = "webauthn.get",
                Challenge = challenge,
                Origin = rp,
            };
            var clientDataJson = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(clientData));

            var sha = SHA256.Create();
            var hashedClientDataJson = sha.ComputeHash(clientDataJson);
            byte[] data = new byte[authData.Length + hashedClientDataJson.Length];
            Buffer.BlockCopy(authData, 0, data, 0, authData.Length);
            Buffer.BlockCopy(hashedClientDataJson, 0, data, authData.Length, hashedClientDataJson.Length);
            byte[] signature = SignData(kty, alg, data, ecdsa, rsa, expandedPrivateKey);

            var userHandle = new byte[16];
            rng.GetBytes(userHandle);

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = authData,
                Signature = signature,
                ClientDataJson = clientDataJson,
                UserHandle = userHandle,
            };

            var lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });
            var existingCredentials = new List<PublicKeyCredentialDescriptor>();
            var cred = new PublicKeyCredentialDescriptor
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 }
            };
            existingCredentials.Add(cred);

            var options = lib.GetAssertionOptions(existingCredentials, null, null);
            options.Challenge = challenge;
            var response = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
            };
            IsUserHandleOwnerOfCredentialIdAsync callback = (args) =>
            {
                return Task.FromResult(true);
            };
            return await lib.MakeAssertionAsync(response, options, cpk.GetBytes(), signCount, callback);
        }

        internal byte[] SignData(COSE.KeyType kty, COSE.Algorithm alg, byte[] data, ECDsa ecdsa = null, RSA rsa = null, byte[] expandedPrivateKey = null)
        {
            byte[] signature = null;
            switch (kty)
            {
                case COSE.KeyType.EC2:
                    {
                        signature = ecdsa.SignData(data, CryptoUtils.algMap[(int)alg]);
                        signature = EcDsaSigFromSig(signature, ecdsa.KeySize);
                        break;
                    }
                case COSE.KeyType.RSA:
                    {
                        RSASignaturePadding padding;
                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                        {
                            case COSE.Algorithm.PS256:
                            case COSE.Algorithm.PS384:
                            case COSE.Algorithm.PS512:
                                padding = RSASignaturePadding.Pss;
                                break;

                            case COSE.Algorithm.RS1:
                            case COSE.Algorithm.RS256:
                            case COSE.Algorithm.RS384:
                            case COSE.Algorithm.RS512:
                                padding = RSASignaturePadding.Pkcs1;
                                break;
                            default:
                                throw new ArgumentOutOfRangeException(nameof(alg), $"Missing or unknown alg {alg}");
                        }
                        signature = rsa.SignData(data, CryptoUtils.algMap[(int)alg], padding);
                        break;
                    }
                case COSE.KeyType.OKP:
                    {
                        signature = Ed25519.Sign(data, expandedPrivateKey);
                        break;
                    }

                default:
                    throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
            }

            return signature;
        }

        internal void MakeEdDSA(out byte[] privateKeySeed, out byte[] publicKey, out byte[] expandedPrivateKey)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                privateKeySeed = new byte[32];
                rng.GetBytes(privateKeySeed);
                publicKey = new byte[32];
                expandedPrivateKey = new byte[64];
                Ed25519.KeyPairFromSeed(out publicKey, out expandedPrivateKey, privateKeySeed);
            }
        }

        internal ECDsa MakeECDsa(COSE.Algorithm alg, COSE.EllipticCurve crv)
        {
            ECCurve curve;
            switch (alg)
            {
                case COSE.Algorithm.ES256:
                    switch (crv)
                    {
                        case COSE.EllipticCurve.P256:
                        case COSE.EllipticCurve.P256K:
                            curve = ECCurve.NamedCurves.nistP256;
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(crv), $"Missing or unknown crv {crv}");
                    }
                    break;
                case COSE.Algorithm.ES384:
                    switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                    {
                        case COSE.EllipticCurve.P384:
                            curve = ECCurve.NamedCurves.nistP384;
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(crv), $"Missing or unknown crv {crv}");
                    }
                    break;
                case COSE.Algorithm.ES512:
                    switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                    {
                        case COSE.EllipticCurve.P521:
                            curve = ECCurve.NamedCurves.nistP521;
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(crv), $"Missing or unknown crv {crv}");
                    }
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(alg), $"Missing or unknown alg {alg}");
            }
            return ECDsa.Create(curve);
        }

        internal CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv, byte[] x, byte[] y)
        {
            return MakeCredentialPublicKey(kty, alg, crv, x, y, null, null);
        }

        internal CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv, byte[] x)
        {
            return MakeCredentialPublicKey(kty, alg, crv, x, null, null, null);
        }

        internal CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, byte[] n, byte[] e)
        {
            return MakeCredentialPublicKey(kty, alg, null, null, null, n, e);
        }

        internal CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve? crv, byte[] x, byte[] y, byte[] n, byte[] e)
        {
            var cpk = CBORObject.NewMap();
            cpk.Add(COSE.KeyCommonParameter.KeyType, kty);
            cpk.Add(COSE.KeyCommonParameter.Alg, alg);
            switch (kty)
            {
                case COSE.KeyType.EC2:
                    cpk.Add(COSE.KeyTypeParameter.X, x);
                    cpk.Add(COSE.KeyTypeParameter.Y, y);
                    cpk.Add(COSE.KeyTypeParameter.Crv, crv);
                    break;
                case COSE.KeyType.RSA:
                    cpk.Add(COSE.KeyTypeParameter.N, n);
                    cpk.Add(COSE.KeyTypeParameter.E, e);
                    break;
                case COSE.KeyType.OKP:
                    cpk.Add(COSE.KeyTypeParameter.X, x);
                    cpk.Add(COSE.KeyTypeParameter.Crv, crv);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(kty), kty, "Invalid COSE key type");
            }
            return new CredentialPublicKey(cpk);
        }
    }
}
