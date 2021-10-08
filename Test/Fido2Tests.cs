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
using System.Text;
using NSec.Cryptography;
using Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Buffers.Binary;

namespace fido2_net_lib.Test
{
    // todo: Create tests and name Facts and json files better.
    public class Fido2Tests
    {
        private static readonly IMetadataService _metadataService;
        private static readonly Fido2Configuration _config;
        public static readonly List<object[]> _validCOSEParameters;

        static Fido2Tests()
        {
            var services = new ServiceCollection();

            var repos = new List<IMetadataRepository>();

            repos.Add(new Fido2MetadataServiceRepository(null));

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
            _validCOSEParameters.Add(new object[3] { COSE.KeyType.EC2, COSE.Algorithm.ES256K, COSE.EllipticCurve.P256K });
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

        public abstract class Attestation
        {
            public CBORObject _attestationObject;
            public CredentialPublicKey _credentialPublicKey;
            public const string rp = "https://www.passwordless.dev";
            public byte[] _challenge;
            public X500DistinguishedName rootDN = new X500DistinguishedName("CN=Testing, O=FIDO2-NET-LIB, C=US");
            public Oid oidIdFidoGenCeAaguid = new Oid("1.3.6.1.4.1.45724.1.1.4");
            //private byte[] asnEncodedAaguid = new byte[] { 0x04, 0x10, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
            //public byte[] asnEncodedAaguid = new byte[] { 0x04, 0x10, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
            public byte[] _asnEncodedAaguid;
            public X509BasicConstraintsExtension caExt = new X509BasicConstraintsExtension(true, true, 2, false);
            public X509BasicConstraintsExtension notCAExt = new X509BasicConstraintsExtension(false, false, 0, false);
            public X509Extension idFidoGenCeAaguidExt;

            public byte[] _rpIdHash
            {
                get
                {
                    byte[] rpId = Encoding.UTF8.GetBytes(rp);
                    return SHA256.Create().ComputeHash(rpId);
                }
            }

            public byte[] _clientDataJson
            {
                get
                {
                    var clientData = new
                    {
                        Type = "webauthn.create",
                        Challenge = _challenge,
                        Origin = rp,
                    };
                    return Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(clientData));
                }
            }
            public byte[] _clientDataHash
            {
                get
                {
                    var sha = SHA256.Create();
                    return sha.ComputeHash(_clientDataJson);
                }
            }

            public byte[] _attToBeSigned
            {
                get
                {
                    byte[] data = new byte[_authData.Length + _clientDataHash.Length];
                    Buffer.BlockCopy(_authData, 0, data, 0, _authData.Length);
                    Buffer.BlockCopy(_clientDataHash, 0, data, _authData.Length, _clientDataHash.Length);
                    return data;
                }
            }

            public byte[] _attToBeSignedHash(HashAlgorithmName alg)
            {
                using (var hasher = CryptoUtils.GetHasher(alg))
                {
                    return hasher.ComputeHash(_attToBeSigned);
                }
            }

            public byte[] _credentialID;
            public const AuthenticatorFlags _flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
            public ushort _signCount;
            public Guid _aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
            public Extensions _exts
            {
                get
                {
                    var extBytes = CBORObject.NewMap().Add("testing", true).EncodeToBytes();
                    return new Extensions(extBytes);
                }
            }
            public byte[] _authData
            {
                get
                {
                    var ad = new AuthenticatorData(_rpIdHash, _flags, _signCount, _acd, _exts);
                    return ad.ToByteArray();
                }
            }
            public AttestedCredentialData _acd
            {
                get
                {
                    return new AttestedCredentialData(_aaguid, _credentialID, _credentialPublicKey);
                }
            }

            public Attestation()
            {                
                var rng = RandomNumberGenerator.Create();
                
                _credentialID = new byte[16];
                rng.GetBytes(_credentialID);

                _challenge = new byte[128];
                rng.GetBytes(_challenge);

                var signCount = new byte[2];
                rng.GetBytes(signCount);
                _signCount = BitConverter.ToUInt16(signCount, 0);

                _attestationObject = CBORObject.NewMap();

                _asnEncodedAaguid = AsnElt.MakeBlob(AttestedCredentialData.AaGuidToBigEndian(_aaguid)).Encode();

                idFidoGenCeAaguidExt = new X509Extension(oidIdFidoGenCeAaguid, _asnEncodedAaguid, false);
            }

            public async Task<Fido2.CredentialMakeResult> MakeAttestationResponse()
            {
                _attestationObject.Set("authData", _authData);

                var attestationResponse = new AuthenticatorAttestationRawResponse
                {
                    Type = PublicKeyCredentialType.PublicKey,
                    Id = new byte[] { 0xf1, 0xd0 },
                    RawId = new byte[] { 0xf1, 0xd0 },
                    Response = new AuthenticatorAttestationRawResponse.ResponseData()
                    {
                        AttestationObject = _attestationObject.EncodeToBytes(),
                        ClientDataJson = _clientDataJson,
                    },
                    Extensions = new AuthenticationExtensionsClientOutputs()
                    {
                        AppID = true,
                        AuthenticatorSelection = true,
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
                
                var credentialMakeResult = await lib.MakeNewCredentialAsync(attestationResponse, origChallenge, callback);

                return credentialMakeResult;
            }

            internal byte[] SignData(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv)
            {
                ECDsa ecdsa = null;
                RSA rsa = null;
                Key privateKey = null;
                byte[] expandedPrivateKey = null, publicKey = null;

                switch (kty)
                {
                    case COSE.KeyType.EC2:
                        {
                            ecdsa = MakeECDsa(alg, crv);
                            break;
                        }
                    case COSE.KeyType.RSA:
                        {
                            rsa = RSA.Create();
                            break;
                        }
                    case COSE.KeyType.OKP:
                        {
                            MakeEdDSA(out var privateKeySeed, out publicKey, out expandedPrivateKey);
                            privateKey = Key.Import(SignatureAlgorithm.Ed25519, expandedPrivateKey, KeyBlobFormat.RawPrivateKey);
                            break;
                        }
                        throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
                }

                return SignData(kty, alg, crv, ecdsa, rsa, privateKey, publicKey);
            }

            internal byte[] SignData(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve curve, ECDsa ecdsa = null, RSA rsa = null, Key expandedPrivateKey = null, byte[] publicKey = null)
            {
                switch (kty)
                {
                    case COSE.KeyType.EC2:
                        {
                            var ecparams = ecdsa.ExportParameters(true);
                            _credentialPublicKey = MakeCredentialPublicKey(kty, alg, curve, ecparams.Q.X, ecparams.Q.Y);
                            var signature = ecdsa.SignData(_attToBeSigned, CryptoUtils.HashAlgFromCOSEAlg((int)alg));
                            return EcDsaSigFromSig(signature, ecdsa.KeySize);
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

                            var rsaparams = rsa.ExportParameters(true);
                            _credentialPublicKey = MakeCredentialPublicKey(kty, alg, rsaparams.Modulus, rsaparams.Exponent);
                            return rsa.SignData(_attToBeSigned, CryptoUtils.HashAlgFromCOSEAlg((int)alg), padding);
                        }
                    case COSE.KeyType.OKP:
                        {
                            _credentialPublicKey = MakeCredentialPublicKey(kty, alg, COSE.EllipticCurve.Ed25519, publicKey);
                            return SignatureAlgorithm.Ed25519.Sign(expandedPrivateKey, _attToBeSigned);
                        }

                    default:
                        throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
                }
            }
        }

        internal static byte[] SignData(COSE.KeyType kty, COSE.Algorithm alg, byte[] data, ECDsa ecdsa = null, RSA rsa = null, byte[] expandedPrivateKey = null)
        {
            switch (kty)
            {
                case COSE.KeyType.EC2:
                    {
                        var signature = ecdsa.SignData(data, CryptoUtils.HashAlgFromCOSEAlg((int)alg));
                        return EcDsaSigFromSig(signature, ecdsa.KeySize);
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
                        return rsa.SignData(data, CryptoUtils.HashAlgFromCOSEAlg((int)alg), padding);
                    }
                case COSE.KeyType.OKP:
                    {
                        Key privateKey = Key.Import(SignatureAlgorithm.Ed25519, expandedPrivateKey, KeyBlobFormat.RawPrivateKey);
                        return SignatureAlgorithm.Ed25519.Sign(privateKey, data);
                    }

                default:
                    throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
            }
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
            var z1 = new[] { AuthenticatorTransport.Ble, AuthenticatorTransport.Usb, AuthenticatorTransport.Nfc, AuthenticatorTransport.Internal };
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

            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationNoneOptions.json"));
            var response = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationNoneResponse.json"));

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
        public void MetadataBLOBPayloadEntry_Can_Be_JSON_Roundtripped()
        {
            var input = new MetadataBLOBPayloadEntry()
            {
                AaGuid = Guid.NewGuid().ToString(),
                MetadataStatement = new MetadataStatement(),
                StatusReports = Array.Empty<StatusReport>(),
                TimeOfLastStatusChange = DateTime.UtcNow.ToString("o")
            };

            input.MetadataStatement.AaGuid = Guid.NewGuid().ToString();
            input.MetadataStatement.Description = "Test entry";
            input.MetadataStatement.AuthenticatorVersion = 1;
            input.MetadataStatement.Upv = new UafVersion[] { new UafVersion
                {
                    Major = 1,
                    Minor = 0,
                } 
            };
            input.MetadataStatement.ProtocolFamily = "foo";
            input.MetadataStatement.AttestationTypes = new string[] { "bar" };
            input.MetadataStatement.AuthenticationAlgorithms = new string[] { "alg0", "alg1" };
            input.MetadataStatement.PublicKeyAlgAndEncodings = new string[] { "example0", "example1" };
            input.MetadataStatement.TcDisplay = new string[] { "transaction","confirmation" };
            input.MetadataStatement.KeyProtection = new string[] { "protector" };
            input.MetadataStatement.MatcherProtection = new string[] { "stuff", "things" };
            input.MetadataStatement.UserVerificationDetails = Array.Empty<VerificationMethodDescriptor[]>();
            input.MetadataStatement.AttestationRootCertificates = new string[] { "..." };

            var json = JsonConvert.SerializeObject(input);

            var output = JsonConvert.DeserializeObject<MetadataBLOBPayloadEntry>(json);

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

        [Fact(Skip = "Need to determine how best to validate expired certificates")]
        public async Task TestAppleAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationAppleResponse.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationAppleOptions.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            var config = new Fido2Configuration { Origin = "https://6cc3c9e7967a.ngrok.io" };
            await o.VerifyAsync(options, config, (x) => Task.FromResult(true), _metadataService, null);
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

        [Fact]
        public async Task TestTrustKeyAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultTrustKeyT110.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsTrustKeyT110.json"));
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
        public async Task TestInvalidU2FAttestationASync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsATKey.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsATKey.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
            var authData = new AuthenticatorData(ad);
            Assert.True(authData.ToByteArray().SequenceEqual(ad));
            var acdBytes = authData.AttestedCredentialData.ToByteArray();
            var acd = new AttestedCredentialData(acdBytes);
            Assert.True(acd.ToByteArray().SequenceEqual(acdBytes));
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

            var sig = SignData(COSE.KeyType.RSA, COSE.Algorithm.RS256, acdBytes, null, rsa, null);

            Assert.True(cpk.Verify(acdBytes, sig));
            sig[sig.Length - 1] ^= 0xff;
            Assert.False(cpk.Verify(acdBytes, sig));
        }

        [Fact]
        public void TestAttestedCredentialDataOKP()
        {
            var aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
            var credentialID = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
            MakeEdDSA(out _, out var publicKey, out var privateKey);
            var cpk = MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519, publicKey);

            var acdFromConst = new AttestedCredentialData(aaguid, credentialID, cpk);
            var acdBytes = acdFromConst.ToByteArray();
            var acdFromBytes = new AttestedCredentialData(acdBytes);
            Assert.True(acdFromBytes.ToByteArray().SequenceEqual(acdFromConst.ToByteArray()));

            var sig = SignData(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, acdBytes, null, null, privateKey);

            Assert.True(cpk.Verify(acdBytes, sig));
            sig[sig.Length - 1] ^= 0xff;
            Assert.False(cpk.Verify(acdBytes, sig));
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

        internal static byte[] EcDsaSigFromSig(byte[] sig, int keySize)
        {
            var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);
            var R = sig.Take(coefficientSize);
            var S = sig.TakeLast(coefficientSize);

            var intR = AsnElt.MakeInteger(R.ToArray());
            var intS = AsnElt.MakeInteger(S.ToArray());
            var ecdsasig = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { intR, intS });
            return ecdsasig.Encode();
        }



        [Fact]
        public void TestAssertionResponse()
        {
            AssertionVerificationResult avr;
            _validCOSEParameters.ForEach(async delegate (object[] param)
            {
                if (param.Length == 3)
                {
                    avr = await MakeAssertionResponse((COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]);
                }
                else
                {
                    avr = await MakeAssertionResponse((COSE.KeyType)param[0], (COSE.Algorithm)param[1]);
                }
                Assert.Equal("", avr.ErrorMessage);
                Assert.Equal("ok", avr.Status);
                Assert.Equal(new byte[] { 0xf1, 0xd0 }, avr.CredentialId);
                Assert.Equal("1", avr.Counter.ToString("X"));
            });
        }

        internal static byte[] CreatePubArea(byte[] type, byte[] alg, byte[] attributes, byte[] policy, byte[] symmetric,
            byte[] scheme, byte[] keyBits, byte[] exponent, byte[] curveID, byte[] kdf, byte[] unique)
        {
            var tpmalg = (TpmAlg)Enum.Parse(typeof(TpmAlg), BinaryPrimitives.ReadUInt16BigEndian(type.AsSpan()).ToString());

            IEnumerable<byte> raw = null;
            var uniqueLen = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(uniqueLen, (UInt16)unique.Length);

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
                    .Concat(BitConverter.GetBytes(exponent[0] + (exponent[1] << 8) + (exponent[2] << 16)))
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

        internal static byte[] CreateCertInfo(byte[] magic, byte[] type, byte[] qualifiedSigner,
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

        
        internal static async Task<AssertionVerificationResult> MakeAssertionResponse(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv = COSE.EllipticCurve.P256, CredentialPublicKey cpk = null, ushort signCount = 0, ECDsa ecdsa = null, RSA rsa = null, byte[] expandedPrivateKey = null)
        {
            const string rp = "https://www.passwordless.dev";
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

        internal static void MakeEdDSA(out byte[] privateKeySeed, out byte[] publicKey, out byte[] expandedPrivateKey)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                privateKeySeed = new byte[32];
                rng.GetBytes(privateKeySeed);
                publicKey = new byte[32];
                var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
                expandedPrivateKey = key.Export(KeyBlobFormat.RawPrivateKey);
                publicKey = key.Export(KeyBlobFormat.RawPublicKey);
            }
        }

        internal static ECDsa MakeECDsa(COSE.Algorithm alg, COSE.EllipticCurve crv)
        {
            ECCurve curve;
            switch (alg)
            {
                case COSE.Algorithm.ES256K:
                    switch (crv)
                    {
                        case COSE.EllipticCurve.P256K:
                            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                            {
                                // see https://github.com/dotnet/runtime/issues/47770
                                throw new PlatformNotSupportedException($"No support currently for secP256k1 on MacOS");
                            }
                            curve = ECCurve.CreateFromFriendlyName("secP256k1");
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(crv), $"Missing or unknown crv {crv}");
                    }
                    break;
                case COSE.Algorithm.ES256:
                    switch (crv)
                    {
                        case COSE.EllipticCurve.P256:
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

        internal static CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv, byte[] x, byte[] y)
        {
            return MakeCredentialPublicKey(kty, alg, crv, x, y, null, null);
        }

        internal static CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv, byte[] x)
        {
            return MakeCredentialPublicKey(kty, alg, crv, x, null, null, null);
        }

        internal static CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, byte[] n, byte[] e)
        {
            return MakeCredentialPublicKey(kty, alg, null, null, null, n, e);
        }

        internal static CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve? crv, byte[] x, byte[] y, byte[] n, byte[] e)
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

        internal static CredentialPublicKey MakeCredentialPublicKey(object[] param)
        {
            var kty = (COSE.KeyType)param[0];
            var alg = (COSE.Algorithm)param[1];
            CredentialPublicKey cpk = null;
            switch (kty)
            {
                case COSE.KeyType.EC2:
                    {
                        var crv = (COSE.EllipticCurve)param[2];
                        var ecdsa = MakeECDsa(alg, crv);
                        var ecparams = ecdsa.ExportParameters(true);
                        cpk = MakeCredentialPublicKey(kty, alg, crv, ecparams.Q.X, ecparams.Q.Y);
                        break;
                    }
                case COSE.KeyType.RSA:
                    {
                        var rsa = RSA.Create();
                        var rsaparams = rsa.ExportParameters(true);
                        cpk = MakeCredentialPublicKey(kty, alg, rsaparams.Modulus, rsaparams.Exponent);
                        break;
                    }
                case COSE.KeyType.OKP:
                    {
                        byte[] publicKey = null;
                        byte[] expandedPrivateKey = null;
                        MakeEdDSA(out var privateKeySeed, out publicKey, out expandedPrivateKey);
                        cpk = MakeCredentialPublicKey(kty, alg, COSE.EllipticCurve.Ed25519, publicKey);
                        break;
                    }
                    throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
            }
            return cpk;
        }
    }
}
