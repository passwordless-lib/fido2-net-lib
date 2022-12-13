using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;

using Moq;

using NSec.Cryptography;

using static Fido2NetLib.AuthenticatorAttestationResponse;

namespace fido2_net_lib.Test;


// todo: Create tests and name Facts and json files better.
public class Fido2Tests
{
    private static readonly IMetadataService _metadataService;
    private static readonly Fido2Configuration _config;
    public static readonly List<(COSE.KeyType, COSE.Algorithm, COSE.EllipticCurve)> _validCOSEParameters;

    static Fido2Tests()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddLogging();
        services.AddHttpClient();

        var provider = services.BuildServiceProvider();

        var distributedCache = provider.GetService<IDistributedCache>();
        var memCache = provider.GetService<IMemoryCache>();

        var repos = new List<IMetadataRepository>
        {
            new Fido2MetadataServiceRepository(provider.GetService<IHttpClientFactory>())
        };

        IMetadataService service = new DistributedCacheMetadataService(
          repos,
          distributedCache,
          memCache,
          provider.GetService<ILogger<DistributedCacheMetadataService>>(),
          new SystemClock());

        _metadataService = service;

        _config = new Fido2Configuration { Origins = new HashSet<string> { "https://localhost:44329" } };

        var noCurve = COSE.EllipticCurve.Reserved;

        _validCOSEParameters = new ()
        {
            new (COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256),
            new (COSE.KeyType.EC2, COSE.Algorithm.ES384, COSE.EllipticCurve.P384),
            new (COSE.KeyType.EC2, COSE.Algorithm.ES512, COSE.EllipticCurve.P521),
            new (COSE.KeyType.RSA, COSE.Algorithm.RS256, noCurve),
            new (COSE.KeyType.RSA, COSE.Algorithm.RS384, noCurve),
            new (COSE.KeyType.RSA, COSE.Algorithm.RS512, noCurve),
            new (COSE.KeyType.RSA, COSE.Algorithm.PS256, noCurve),
            new (COSE.KeyType.RSA, COSE.Algorithm.PS384, noCurve),
            new (COSE.KeyType.RSA, COSE.Algorithm.PS512, noCurve),
            new (COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519),
            new (COSE.KeyType.EC2, COSE.Algorithm.ES256K, COSE.EllipticCurve.P256K)
        };
    }
   
    private async Task<T> GetAsync<T>(string filename)
    {
        return JsonSerializer.Deserialize<T>(await File.ReadAllTextAsync(filename));
    }

    public abstract class Attestation
    {
        public CborMap _attestationObject;
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

        public byte[] _rpIdHash => SHA256.HashData(Encoding.UTF8.GetBytes(rp));

        public byte[] _clientDataJson
        {
            get
            {
                return JsonSerializer.SerializeToUtf8Bytes(new
                {
                    type = "webauthn.create",
                    challenge = _challenge,
                    origin = rp
                });
            }
        }

        public byte[] _clientDataHash => SHA256.HashData(_clientDataJson);

        public byte[] _attToBeSigned => DataHelper.Concat(_authData, _clientDataHash);

        public byte[] _attToBeSignedHash(HashAlgorithmName alg)
        {
            return CryptoUtils.HashData(alg, _attToBeSigned);                
        }

        public byte[] _credentialID;
        public const AuthenticatorFlags _flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
        public ushort _signCount;
        public Guid _aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
        public Extensions _exts
        {
            get
            {
                var extBytes = new CborMap { { "testing", true } }.Encode();
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
            _credentialID = RandomNumberGenerator.GetBytes(16);
            _challenge = RandomNumberGenerator.GetBytes(128);

            byte[] signCount = RandomNumberGenerator.GetBytes(2);

            _signCount = BitConverter.ToUInt16(signCount, 0);

            _attestationObject = new CborMap();

            _asnEncodedAaguid = AsnHelper.GetBlob(AttestedCredentialData.AaGuidToBigEndian(_aaguid));

            idFidoGenCeAaguidExt = new X509Extension(oidIdFidoGenCeAaguid, _asnEncodedAaguid, false);
        }

        public async Task<Fido2.CredentialMakeResult> MakeAttestationResponseAsync()
        {
            _attestationObject.Set("authData", new CborByteString(_authData));

            var attestationResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = _attestationObject.Encode(),
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
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = _challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
                {
                    new PubKeyCredParam(COSE.Algorithm.ES256),
                    new PubKeyCredParam(COSE.Algorithm.ES384),
                    new PubKeyCredParam(COSE.Algorithm.ES512),
                    new PubKeyCredParam(COSE.Algorithm.RS1),
                    new PubKeyCredParam(COSE.Algorithm.RS256),
                    new PubKeyCredParam(COSE.Algorithm.RS384),
                    new PubKeyCredParam(COSE.Algorithm.RS512),
                    new PubKeyCredParam(COSE.Algorithm.PS256),
                    new PubKeyCredParam(COSE.Algorithm.PS384),
                    new PubKeyCredParam(COSE.Algorithm.PS512),
                    new PubKeyCredParam(COSE.Algorithm.EdDSA),
                    new PubKeyCredParam(COSE.Algorithm.ES256K),
                },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
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

            IFido2 lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });
            
            var credentialMakeResult = await lib.MakeNewCredentialAsync(attestationResponse, origChallenge, callback);

            return credentialMakeResult;
        }

        internal byte[] SignData(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv)
        {
            ECDsa ecdsa = null;
            RSA rsa = null;
            Key privateKey = null;
            byte[] publicKey = null;

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
                        MakeEdDSA(out var privateKeySeed, out publicKey, out byte[] expandedPrivateKey);
                        privateKey = Key.Import(SignatureAlgorithm.Ed25519, expandedPrivateKey, KeyBlobFormat.RawPrivateKey);
                        break;
                    }
                default:
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
                        var signature = ecdsa.SignData(_attToBeSigned, CryptoUtils.HashAlgFromCOSEAlg(alg));
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
                        return rsa.SignData(_attToBeSigned, CryptoUtils.HashAlgFromCOSEAlg(alg), padding);
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
                    var signature = ecdsa.SignData(data, CryptoUtils.HashAlgFromCOSEAlg(alg));
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
                    return rsa.SignData(data, CryptoUtils.HashAlgFromCOSEAlg(alg), padding);
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
        var x2 = new AuthenticatorSelection
        {
            UserVerification = UserVerificationRequirement.Discouraged
        };

        var json = JsonSerializer.Serialize(x2);
        var c3 = JsonSerializer.Deserialize<AuthenticatorSelection>(json);

        Assert.Equal(UserVerificationRequirement.Discouraged, c3.UserVerification);

        Assert.NotEqual(UserVerificationRequirement.Required, c3.UserVerification);

        // Assert.True("discouraged" == UserVerificationRequirement.Discouraged);
        // Assert.False("discouraged" != UserVerificationRequirement.Discouraged);

        Assert.False(UserVerificationRequirement.Required == UserVerificationRequirement.Discouraged);
        Assert.True(UserVerificationRequirement.Required != UserVerificationRequirement.Discouraged);

        // testing where string and membername mismatch

        var y1 = AuthenticatorAttachment.CrossPlatform;
        var yjson = JsonSerializer.Serialize(y1);
        Assert.Equal("\"cross-platform\"", yjson);

        var y2 = JsonSerializer.Deserialize<AuthenticatorAttachment>(yjson);

        Assert.Equal(AuthenticatorAttachment.CrossPlatform, y2);

        // test list of typedstrings
        var z1 = new[] { 
            AuthenticatorTransport.Ble, 
            AuthenticatorTransport.Usb, 
            AuthenticatorTransport.Nfc,
            AuthenticatorTransport.Internal 
        };

        var zjson = JsonSerializer.Serialize(z1);
        var z2 = JsonSerializer.Deserialize<AuthenticatorTransport[]>(zjson);

        Assert.All(z2, (x) => z1.Contains(x));
        Assert.True(z1.SequenceEqual(z2));
    }

    [Fact]
    public async Task TestFido2AssertionAsync()
    {
        //var existingKey = "45-43-53-31-20-00-00-00-0E-B4-F3-73-C2-AC-7D-F7-7E-7D-17-D3-A3-A2-CC-AB-E5-C6-B1-42-ED-10-AC-7C-15-72-39-8D-75-C6-5B-B9-76-09-33-A0-30-F2-44-51-C8-31-AF-72-9B-4F-7B-AB-4F-85-2D-7D-1F-E0-B5-BD-A3-3D-0E-D6-18-04-CD-98";

        //var key2 = "45-43-53-31-20-00-00-00-1D-60-44-D7-92-A0-0C-1E-3B-F9-58-5A-28-43-92-FD-F6-4F-BB-7F-8E-86-33-38-30-A4-30-5D-4E-2C-71-E3-53-3C-7B-98-81-99-FE-A9-DA-D9-24-8E-04-BD-C7-86-40-D3-03-1E-6E-00-81-7D-85-C3-A2-19-C9-21-85-8D";
        //var key2 = "45-43-53-31-20-00-00-00-A9-E9-12-2A-37-8A-F0-74-E7-BA-52-54-B0-91-55-46-DB-21-E5-2C-01-B8-FB-69-CD-E5-ED-02-B6-C3-16-E3-1A-59-16-C1-43-87-0D-04-B9-94-7F-CF-56-E5-AA-5E-96-8C-5B-27-8F-83-F4-E2-50-AB-B3-F6-28-A1-F8-9E";

        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationNoneOptions.json"));
        var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationNoneResponse.json"));

        var o = AuthenticatorAttestationResponse.Parse(response);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);

        var credId = "F1-3C-7F-08-3C-A2-29-E0-B4-03-E8-87-34-6E-FC-7F-98-53-10-3A-30-91-75-67-39-7A-D1-D8-AF-87-04-61-87-EF-95-31-85-60-F3-5A-1A-2A-CF-7D-B0-1D-06-B9-69-F9-AB-F4-EC-F3-07-3E-CF-0F-71-E8-84-E8-41-20";
        var allowedCreds = new List<PublicKeyCredentialDescriptor>() {
            new PublicKeyCredentialDescriptor()
            {
                Id = Convert.FromHexString(credId.Replace("-", "")),
                Type = PublicKeyCredentialType.PublicKey
            }
        };

        // assertion

        var aoptions = await GetAsync<AssertionOptions>("./assertionNoneOptions.json");
        var aresponse = await GetAsync<AuthenticatorAssertionRawResponse>("./assertionNoneResponse.json");
    }

    [Fact]
    public void TestAppleAppAttestDev()
    {
        var b64 = "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";
        var cbor = Convert.FromBase64String(b64);
        var json = (CborMap) CborObject.Decode(cbor);

        var AttestationObject = new ParsedAttestationObject
        (
            fmt: (string)json["fmt"],
            attStmt: (CborMap)json["attStmt"],
            authData: (byte[])json["authData"]
        );

        var clientDataJson = SHA256.HashData(Encoding.UTF8.GetBytes("This is a test. This will need to be removed before merging."));

        var verifier = new AppleAppAttest();
        (AttestationType attType, X509Certificate[] trustPath) = verifier.Verify(AttestationObject.AttStmt, AttestationObject.AuthData, clientDataJson);
        Assert.True(attType.Equals(AttestationType.Basic));
    }

    [Fact]
    public void TestAppleAppAttestProd()
    {
        var b64 = "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";
        var cbor = Convert.FromBase64String(b64);
        var json = (CborMap)CborObject.Decode(cbor);

        var AttestationObject = new ParsedAttestationObject
        (
            fmt      : (string)json["fmt"],
            attStmt  : (CborMap)json["attStmt"],
            authData : (byte[])json["authData"]
        );

        var clientDataJson = SHA256.HashData(Encoding.UTF8.GetBytes("1234567890abcdefgh"));

        var verifier = new AppleAppAttest();
        var ex = Assert.Throws<Fido2VerificationException>(() => { 
            (AttestationType attType, X509Certificate[] trustPath) = verifier.Verify(AttestationObject.AttStmt, AttestationObject.AuthData, clientDataJson); 
        });

        const string windowsErrorMessage = "Failed to build chain in Apple AppAttest attestation: A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file.";
        const string cryptoKitErrorMessage = "Failed to build chain in Apple AppAttest attestation: An expired certificate was detected.";
        const string linuxErrorMessage     = "Failed to build chain in Apple AppAttest attestation: certificate has expired";

        Assert.True(ex.Message is windowsErrorMessage or cryptoKitErrorMessage or linuxErrorMessage);
    }

    [Fact]
    public async Task TestParsingAsync()
    {
        var jsonPost = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./json1.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./options1.json"));

        Assert.NotNull(jsonPost);

        var o = AuthenticatorAttestationResponse.Parse(jsonPost);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);
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

        var json = JsonSerializer.Serialize(input);

        var output = JsonSerializer.Deserialize<MetadataBLOBPayloadEntry>(json);

        Assert.Equal(input.AaGuid, output.AaGuid);

    }

    [Fact]
    public void TestAuthenticatorDataPa2rsing()
    {
        var bs = new byte[] { 1, 2, 3 };
        var x = new CborMap { { "bytes", bs } };
        var s = (byte[])x["bytes"];

        Assert.Equal(s, bs);
    }

    [Fact]
    public async Task TestU2FAttestationAsync()
    {
        var jsonPost = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationResultsU2F.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationOptionsU2F.json"));
        var o = AuthenticatorAttestationResponse.Parse(jsonPost);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);
        byte[] ad = o.AttestationObject.AuthData;
        // TODO : Why read ad ? Is the test finished ?
    }
    [Fact]
    public async Task TestPackedAttestationAsync()
    {
        var jsonPost = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationResultsPacked.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationOptionsPacked.json"));
        var o = AuthenticatorAttestationResponse.Parse(jsonPost);
        options.PubKeyCredParams.Add(new PubKeyCredParam(COSE.Algorithm.RS1, PublicKeyCredentialType.PublicKey));
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);
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
        var jsonPost = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationResultsNone.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationOptionsNone.json"));

        var o = AuthenticatorAttestationResponse.Parse(jsonPost);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);
    }
    [Fact]
    public async Task TestTPMSHA256AttestationAsync()
    {
        var jsonPost = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationTPMSHA256Response.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationTPMSHA256Options.json"));
        var o = AuthenticatorAttestationResponse.Parse(jsonPost);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);
        byte[] ad = o.AttestationObject.AuthData;
        // TODO : Why read ad ? Is the test finished ?
    }
    [Fact]
    public async Task TestTPMSHA1AttestationAsync()
    {
        var jsonPost = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationTPMSHA1Response.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationTPMSHA1Options.json"));
        var o = AuthenticatorAttestationResponse.Parse(jsonPost);
        options.PubKeyCredParams.Add(new PubKeyCredParam(COSE.Algorithm.RS1, PublicKeyCredentialType.PublicKey));
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);
        byte[] ad = o.AttestationObject.AuthData;
        // TODO : Why read ad ? Is the test finished ?
    }
    [Fact]
    public async Task TestAndroidKeyAttestationAsync()
    {
        var jsonPost = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationAndroidKeyResponse.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationAndroidKeyOptions.json"));
        var o = AuthenticatorAttestationResponse.Parse(jsonPost);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);
        byte[] ad = o.AttestationObject.AuthData;
        // TODO : Why read ad ? Is the test finished ?
    }

    [Fact]
    public async Task TaskPackedAttestation512()
    {
        var jsonPost = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationResultsPacked512.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationOptionsPacked512.json"));
        var o = AuthenticatorAttestationResponse.Parse(jsonPost);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);
        byte[] ad = o.AttestationObject.AuthData;
        // TODO : Why read ad ? Is the test finished ?
    }

    [Fact]
    public async Task TestTrustKeyAttestationAsync()
    {
        var jsonPost = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationResultTrustKeyT110.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationOptionsTrustKeyT110.json"));
        var o = AuthenticatorAttestationResponse.Parse(jsonPost);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);
        byte[] ad = o.AttestationObject.AuthData;
        var authData = new AuthenticatorData(ad);
        Assert.True(authData.ToByteArray().SequenceEqual(ad));
        var acdBytes = authData.AttestedCredentialData.ToByteArray();
        var acd = new AttestedCredentialData(acdBytes);
        Assert.True(acd.ToByteArray().SequenceEqual(acdBytes));
    }

    [Fact]
    public async Task TestInvalidU2FAttestationAsync()
    {
        var jsonPost = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationResultsATKey.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationOptionsATKey.json"));
        var o = AuthenticatorAttestationResponse.Parse(jsonPost);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), _metadataService, null, CancellationToken.None);
        byte[] ad = o.AttestationObject.AuthData;
        var authData = new AuthenticatorData(ad);
        Assert.True(authData.ToByteArray().SequenceEqual(ad));
        var acdBytes = authData.AttestedCredentialData.ToByteArray();
        var acd = new AttestedCredentialData(acdBytes);
        Assert.True(acd.ToByteArray().SequenceEqual(acdBytes));
    }

    [Fact]
    public async Task TestMdsStatusReportsSuccessAsync()
    {
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationNoneOptions.json"));
        var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationNoneResponse.json"));

        var mockMetadataService = new Mock<IMetadataService>(MockBehavior.Strict);
        mockMetadataService.Setup(m => m.GetEntryAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MetadataBLOBPayloadEntry()
            {
                StatusReports = new StatusReport[]
                {
                    new StatusReport() { Status = AuthenticatorStatus.FIDO_CERTIFIED }
                }
            });
        mockMetadataService.Setup(m => m.ConformanceTesting()).Returns(false);

        var o = AuthenticatorAttestationResponse.Parse(response);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), mockMetadataService.Object, null, CancellationToken.None);
    }

    [Fact]
    public async Task TestMdsStatusReportsUndesiredAsync()
    {
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationNoneOptions.json"));
        var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationNoneResponse.json"));

        var mockMetadataService = new Mock<IMetadataService>(MockBehavior.Strict);
        mockMetadataService.Setup(m => m.GetEntryAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MetadataBLOBPayloadEntry()
            {
                StatusReports = new StatusReport[]
                {
                    new StatusReport() { Status = AuthenticatorStatus.FIDO_CERTIFIED },
                    new StatusReport() { Status = AuthenticatorStatus.REVOKED }
                }
            });
        mockMetadataService.Setup(m => m.ConformanceTesting()).Returns(false);

        var o = AuthenticatorAttestationResponse.Parse(response);
        await Assert.ThrowsAsync<UndesiredMetdatataStatusFido2VerificationException>(() =>
            o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), mockMetadataService.Object, null, CancellationToken.None));
    }

    [Fact]
    public async Task TestMdsStatusReportsUndesiredFixedAsync()
    {
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationNoneOptions.json"));
        var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationNoneResponse.json"));

        var mockMetadataService = new Mock<IMetadataService>(MockBehavior.Strict);
        mockMetadataService.Setup(m => m.GetEntryAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MetadataBLOBPayloadEntry()
            {
                StatusReports = new StatusReport[]
                {
                    new StatusReport() { Status = AuthenticatorStatus.FIDO_CERTIFIED },
                    new StatusReport() { Status = AuthenticatorStatus.REVOKED },
                    new StatusReport() { Status = AuthenticatorStatus.UPDATE_AVAILABLE }
                }
            });
        mockMetadataService.Setup(m => m.ConformanceTesting()).Returns(false);

        var o = AuthenticatorAttestationResponse.Parse(response);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), mockMetadataService.Object, null, CancellationToken.None);
    }

    [Fact]
    public async Task TestMdsStatusReportsNullAsync()
    {
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationNoneOptions.json"));
        var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationNoneResponse.json"));

        var mockMetadataService = new Mock<IMetadataService>(MockBehavior.Strict);
        mockMetadataService.Setup(m => m.GetEntryAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>())).ReturnsAsync((MetadataBLOBPayloadEntry)null);
        mockMetadataService.Setup(m => m.ConformanceTesting()).Returns(false);

        var o = AuthenticatorAttestationResponse.Parse(response);
        await o.VerifyAsync(options, _config, (x, cancellationToken) => Task.FromResult(true), mockMetadataService.Object, null, CancellationToken.None);
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
        sig[^1] ^= 0xff;
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
        sig[^1] ^= 0xff;
        Assert.False(cpk.Verify(acdBytes, sig));
    }

    [Fact]
    public void TestAuthenticatorData()
    {
        var rpId = "fido2.azurewebsites.net/"u8;
        var rpIdHash = SHA256.HashData(rpId);
        var flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
        const ushort signCount = 0xf1d0;
        var aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
        var credentialID = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
        var ecdsa = MakeECDsa(COSE.Algorithm.ES256, COSE.EllipticCurve.P256);
        var ecparams = ecdsa.ExportParameters(true);
        var cpk = MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecparams.Q.X, ecparams.Q.Y);

        var acd = new AttestedCredentialData(aaguid, credentialID, cpk);
        var extBytes = new CborMap { { "testing", true } }.Encode();
        var exts = new Extensions(extBytes);

        var ad = new AuthenticatorData(rpIdHash, flags, signCount, acd, exts);
        Assert.True(ad.RpIdHash.SequenceEqual(rpIdHash));
        Assert.True(ad.HasAttestedCredentialData | ad.UserPresent | ad.UserVerified | ad.HasExtensionsData);
        Assert.True(ad.SignCount == signCount);
        Assert.True(ad.AttestedCredentialData.ToByteArray().SequenceEqual(acd.ToByteArray()));
        Assert.True(ad.Extensions.GetBytes().SequenceEqual(extBytes));
    }

    internal static byte[] EcDsaSigFromSig(ReadOnlySpan<byte> sig, int keySize)
    {
        var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);
        var r = sig.Slice(0, coefficientSize);
        var s = sig.Slice(sig.Length - coefficientSize);

        var writer = new AsnWriter(AsnEncodingRules.BER);

        ReadOnlySpan<byte> zero = new byte[1] { 0 };

        using (writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(r.TrimStart(zero));
            writer.WriteIntegerUnsigned(s.TrimStart(zero));
        }

        return writer.Encode();
    }

    [Fact]
    public void TestAssertionResponse()
    {
        AssertionVerificationResult avr;
        _validCOSEParameters.ForEach(async ((COSE.KeyType, COSE.Algorithm, COSE.EllipticCurve) param) =>
        {
            var (type, alg, curve) = param;

            // No support for P256K on OSX
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) && curve == COSE.EllipticCurve.P256K)
                return;

            if (curve != default)
            {
                avr = await MakeAssertionResponseAsync(type, alg, curve);
            }
            else
            {
                avr = await MakeAssertionResponseAsync(type, alg);
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
        var tpmalg = (TpmAlg)Enum.ToObject(typeof(TpmAlg), BinaryPrimitives.ReadUInt16BigEndian(type));

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
        var raw = new MemoryStream();

        raw.Write(magic);
        raw.Write(type);
        raw.Write(qualifiedSigner);
        raw.Write(extraData);
        raw.Write(clock);
        raw.Write(resetCount);
        raw.Write(restartCount);
        raw.Write(safe);
        raw.Write(firmwareRevision);
        raw.Write(tPM2BName);
        raw.Write(attestedQualifiedNameBuffer);

        return raw.ToArray();
    }
    
    internal static async Task<AssertionVerificationResult> MakeAssertionResponseAsync(
        COSE.KeyType kty,
        COSE.Algorithm alg,
        COSE.EllipticCurve crv = COSE.EllipticCurve.P256,
        CredentialPublicKey cpk = null,
        ushort signCount = 0,
        ECDsa ecdsa = null,
        RSA rsa = null,
        byte[] expandedPrivateKey = null)
    {
        const string rp = "https://www.passwordless.dev";
        byte[] rpId = Encoding.UTF8.GetBytes(rp);
        var rpIdHash = SHA256.HashData(rpId);
        var flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
        var aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
        var credentialID = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };
        if (cpk == null)
        {
            switch (kty)
            {
                case COSE.KeyType.EC2:
                    {
                        ecdsa ??= MakeECDsa(alg, crv);
                        
                        var ecparams = ecdsa.ExportParameters(true);
                        cpk = MakeCredentialPublicKey(kty, alg, crv, ecparams.Q.X, ecparams.Q.Y);
                        break;
                    }
                case COSE.KeyType.RSA:
                    {
                        rsa ??= RSA.Create();
                        
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
                default:
                    throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
            }
        }
        var acd = new AttestedCredentialData(aaguid, credentialID, cpk);
        var extBytes = new CborMap { { "testing", true } }.Encode();
        var exts = new Extensions(extBytes);

        var ad = new AuthenticatorData(rpIdHash, flags, (uint)(signCount + 1), acd, exts);
        var authData = ad.ToByteArray();

        var challenge = new byte[128];
        RandomNumberGenerator.Fill(challenge);

        var clientData = new
        {
            type = "webauthn.get",
            challenge = challenge,
            origin = rp,
        };
        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(clientData);

        var hashedClientDataJson = SHA256.HashData(clientDataJson);
        byte[] data = new byte[authData.Length + hashedClientDataJson.Length];
        Buffer.BlockCopy(authData, 0, data, 0, authData.Length);
        Buffer.BlockCopy(hashedClientDataJson, 0, data, authData.Length, hashedClientDataJson.Length);
        byte[] signature = SignData(kty, alg, data, ecdsa, rsa, expandedPrivateKey);

        var userHandle = new byte[16];
        RandomNumberGenerator.Fill(userHandle);

        var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        {
            AuthenticatorData = authData,
            Signature = signature,
            ClientDataJson = clientDataJson,
            UserHandle = userHandle,
        };

        IFido2 lib = new Fido2(new Fido2Configuration()
        {
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
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
        IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };
        return await lib.MakeAssertionAsync(response, options, cpk.GetBytes(), null, signCount, callback);
    }

    internal static void MakeEdDSA(out byte[] privateKeySeed, out byte[] publicKey, out byte[] expandedPrivateKey)
    {           
        privateKeySeed = new byte[32];
        RandomNumberGenerator.Fill(privateKeySeed);
        var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        expandedPrivateKey = key.Export(KeyBlobFormat.RawPrivateKey);
        publicKey = key.Export(KeyBlobFormat.RawPublicKey);            
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
                        if (OperatingSystem.IsMacOS())
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
                curve = crv switch
                {
                    COSE.EllipticCurve.P256 => ECCurve.NamedCurves.nistP256,
                    _ => throw new ArgumentOutOfRangeException(nameof(crv), $"Missing or unknown crv {crv}"),
                };
                break;
            case COSE.Algorithm.ES384:
                curve = crv switch // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                {
                    COSE.EllipticCurve.P384 => ECCurve.NamedCurves.nistP384,
                    _ => throw new ArgumentOutOfRangeException(nameof(crv), $"Missing or unknown crv {crv}"),
                };
                break;
            case COSE.Algorithm.ES512:
                curve = crv switch // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                {
                    COSE.EllipticCurve.P521 => ECCurve.NamedCurves.nistP521,
                    _ => throw new ArgumentOutOfRangeException(nameof(crv), $"Missing or unknown crv {crv}"),
                };
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
        var cpk = new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, kty },
            { COSE.KeyCommonParameter.Alg, alg }
        };

        switch (kty)
        {
            case COSE.KeyType.EC2:
                cpk.Add(COSE.KeyTypeParameter.X, x);
                cpk.Add(COSE.KeyTypeParameter.Y, y);
                cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)crv);
                break;
            case COSE.KeyType.RSA:
                cpk.Add(COSE.KeyTypeParameter.N, n);
                cpk.Add(COSE.KeyTypeParameter.E, e);
                break;
            case COSE.KeyType.OKP:
                cpk.Add(COSE.KeyTypeParameter.X, x);
                cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)crv);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(kty), kty, "Invalid COSE key type");
        }
        return new CredentialPublicKey(cpk);
    }

    internal static CredentialPublicKey MakeCredentialPublicKey((COSE.KeyType, COSE.Algorithm, COSE.EllipticCurve) param)
    {
        var (kty, alg, crv) = param;

        CredentialPublicKey cpk;
        switch (kty)
        {
            case COSE.KeyType.EC2:
                {
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
                    MakeEdDSA(out var privateKeySeed, out byte[] publicKey, out _);
                    cpk = MakeCredentialPublicKey(kty, alg, COSE.EllipticCurve.Ed25519, publicKey);
                    break;
                }
            default:
                throw new ArgumentException(nameof(kty), $"Missing or unknown kty {kty}");
        }
        return cpk;
    }
}
