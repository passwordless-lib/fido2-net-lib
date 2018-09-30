using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    public enum AuthenticatorStatus
    {
        NOT_FIDO_CERTIFIED,
        FIDO_CERTIFIED,
        USER_VERIFICATION_BYPASS,
        ATTESTATION_KEY_COMPROMISE,
        USER_KEY_REMOTE_COMPROMISE,
        USER_KEY_PHYSICAL_COMPROMISE,
        UPDATE_AVAILABLE,
        REVOKED,
        SELF_ASSERTION_SUBMITTED,
        FIDO_CERTIFIED_L1,
        FIDO_CERTIFIED_L1plus,
        FIDO_CERTIFIED_L2,
        FIDO_CERTIFIED_L2plus,
        FIDO_CERTIFIED_L3,
        FIDO_CERTIFIED_L3plus
    };

    public enum UndesiredAuthenticatorStatus
    {
        ATTESTATION_KEY_COMPROMISE = AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE,
        USER_VERIFICATION_BYPASS = AuthenticatorStatus.USER_VERIFICATION_BYPASS,
        USER_KEY_REMOTE_COMPROMISE = AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE,
        USER_KEY_PHYSICAL_COMPROMISE = AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE,
        REVOKED = AuthenticatorStatus.REVOKED
    };
    public enum MetadataAttestationType
    {
        ATTESTATION_BASIC_FULL = 0x3e07,
        ATTESTATION_BASIC_SURROGATE = 0x3e08
    }
    public class StatusReport
    {
        [JsonProperty("status", Required = Required.Always)]
        public AuthenticatorStatus Status { get; set; }
        [JsonProperty("effectiveDate")]
        public string EffectiveDate { get; set; }
        [JsonProperty("certificate")]
        public string Certificate { get; set; }
        [JsonProperty("url")]
        public string Url { get; set; }
        [JsonProperty("certificationDescriptor")]
        public string CertificationDescriptor { get; set; }
        [JsonProperty("certificateNumber")]
        public string CertificateNumber { get; set; }
        [JsonProperty("certificationPolicyVersion")]
        public string CertificationPolicyVersion { get; set; }
        [JsonProperty("certificationRequirementsVersion")]
        public string CertificationRequirementsVersion { get; set; }
    }
    public class BiometricStatusReport
    {
        [JsonProperty("certLevel", Required = Required.Always)]
        public ushort CertLevel { get; set; }
        [JsonProperty("modality", Required = Required.Always)]
        public ulong Modality { get; set; }
        [JsonProperty("effectiveDate")]
        public string EffectiveDate { get; set; }
        [JsonProperty("certificationDescriptor")]
        public string CertificationDescriptor { get; set; }
        [JsonProperty("certificateNumber")]
        public string CertificateNumber { get; set; }
        [JsonProperty("certificationPolicyVersion")]
        public string CertificationPolicyVersion { get; set; }
        [JsonProperty("certificationRequirementsVersion")]
        public string CertificationRequirementsVersion { get; set; }
    }
    public class MetadataTOCPayloadEntry
    {
        [JsonProperty("aaid")]
        public string Aaid { get; set; }
        [JsonProperty("aaguid")]
        public string AaGuid { get; set; }
        [JsonProperty("attestationCertificateKeyIdentifiers")]
        public string[] AttestationCertificateKeyIdentifiers { get; set; }
        [JsonProperty("hash")]
        public string Hash { get; set; }
        [JsonProperty("url")]
        public string Url { get; set; }
        [JsonProperty("biometricStatusReports")]
        public BiometricStatusReport[] BiometricStatusReports { get; set; }
        [JsonProperty("statusReports", Required = Required.Always)]
        public StatusReport[] StatusReports { get; set; }
        [JsonProperty("timeOfLastStatusChange", Required = Required.Always)]
        public string TimeOfLastStatusChange { get; set; }
        [JsonProperty("rogueListURL")]
        public string RogueListURL { get; set; }
        [JsonProperty("rogueListHash")]
        public string RogueListHash { get; set; }
        [JsonProperty("metadataStatement")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public MetadataStatement MetadataStatement { get; set; }
    }
    public class RogueListEntry
    {
        [JsonProperty("sk", Required = Required.Always)]
        public string Sk { get; set; }
        [JsonProperty("date", Required = Required.Always)]
        public string Date { get; set; }
    }
    public class MetadataTOCPayload
    {
        [JsonProperty("legalHeader")]
        public string LegalHeader { get; set; }
        [JsonProperty("no", Required = Required.Always)]
        public int Number { get; set; }
        [JsonProperty("nextUpdate", Required = Required.Always)]
        public string NextUpdate { get; set; }
        [JsonProperty("entries", Required = Required.Always)]
        public MetadataTOCPayloadEntry[] Entries { get; set; }
    }

    public class AlternativeDescriptions
    {
        [JsonProperty("alternativeDescriptions")]
        public System.Collections.Generic.Dictionary<string, string> IETFLanguageCodesMembers { get; set; }
    }

    public class Version
    {
        [JsonProperty("major")]
        public ushort Major { get; set; }
        [JsonProperty("minor")]
        public ushort Minor { get; set; }
    }
    public class CodeAccuracyDescriptor
    {
        [JsonProperty("base", Required = Required.Always)]
        public ushort Base { get; set; }
        [JsonProperty("minLength", Required = Required.Always)]
        public ushort MinLength { get; set; }
        [JsonProperty("maxRetries")]
        public ushort MaxRetries { get; set; }
        [JsonProperty("blockSlowdown")]
        public ushort BlockSlowdown { get; set; }
    }
    public class BiometricAccuracyDescriptor
    {
        [JsonProperty("selfAttestedFRR ")]
        public double SelfAttestedFRR { get; set; }
        [JsonProperty("selfAttestedFAR ")]
        public double SelfAttestedFAR { get; set; }
        [JsonProperty("maxTemplates")]
        public ushort MaxTemplates { get; set; }
        [JsonProperty("maxRetries")]
        public ushort MaxRetries { get; set; }
        [JsonProperty("blockSlowdown")]
        public ushort BlockSlowdown { get; set; }
    }
    public class PatternAccuracyDescriptor
    {
        [JsonProperty("minComplexity", Required = Required.Always)]
        public ulong MinComplexity { get; set; }
        [JsonProperty("maxRetries")]
        public ushort MaxRetries { get; set; }
        [JsonProperty("blockSlowdown")]
        public ushort BlockSlowdown { get; set; }
    }
    public class VerificationMethodDescriptor
    {
        [JsonProperty("userVerification", Required = Required.Always)]
        public ulong UserVerification { get; set; }
        [JsonProperty("caDesc")]
        public CodeAccuracyDescriptor CaDesc { get; set; }
        [JsonProperty("baDesc")]
        public BiometricAccuracyDescriptor BaDesc { get; set; }
        [JsonProperty("paDesc")]
        public PatternAccuracyDescriptor PaDesc { get; set; }
    }
    public class VerificationMethodANDCombinations
    {
        [JsonProperty("verificationMethodANDCombinations")]
        public VerificationMethodDescriptor[] VerificationMethodAndCombinations { get; set; }
    }
    public class rgbPaletteEntry
    {
        [JsonProperty("r", Required = Required.Always)]
        public ushort R { get; set; }
        [JsonProperty("g", Required = Required.Always)]
        public ushort G { get; set; }
        [JsonProperty("b", Required = Required.Always)]
        public ushort B { get; set; }
    }
    public class DisplayPNGCharacteristicsDescriptor
    {
        [JsonProperty("width", Required = Required.Always)]
        public ulong Width { get; set; }
        [JsonProperty("height", Required = Required.Always)]
        public ulong Height { get; set; }
        [JsonProperty("bitDepth", Required = Required.Always)]
        public byte BitDepth { get; set; }
        [JsonProperty("colorType", Required = Required.Always)]
        public byte ColorType { get; set; }
        [JsonProperty("compression", Required = Required.Always)]
        public byte Compression { get; set; }
        [JsonProperty("filter", Required = Required.Always)]
        public byte Filter { get; set; }
        [JsonProperty("interlace", Required = Required.Always)]
        public byte Interlace { get; set; }
        [JsonProperty("plte")]
        public rgbPaletteEntry[] Plte { get; set; } 
    }
    public class EcdaaTrustAnchor
    {
        [JsonProperty("x", Required = Required.Always)]
        public string X { get; set; }
        [JsonProperty("y", Required = Required.Always)]
        public string Y { get; set; }
        [JsonProperty("c", Required = Required.Always)]
        public string C { get; set; }
        [JsonProperty("sx", Required = Required.Always)]
        public string SX { get; set; }
        [JsonProperty("sy", Required = Required.Always)]
        public string SY { get; set; }
        [JsonProperty("G1Curve", Required = Required.Always)]
        public string G1Curve { get; set; }
    }
    public class ExtensionDescriptor
    {
        [JsonProperty("id", Required = Required.Always)]
        public string Id { get; set; }
        [JsonProperty("tag")]
        public ushort Tag { get; set; }
        [JsonProperty("data")]
        public string Data { get; set; }
        [JsonProperty("fail_if_unknown", Required = Required.Always)]
        public bool Fail_If_Unknown { get; set; }
    }

    public class MetadataStatement
    {
        [JsonProperty("legalHeader")]
        public string LegalHeader { get; set; }
        [JsonProperty("aaid")]
        public string Aaid { get; set; }
        [JsonProperty("aaguid")]
        public string AaGuid { get; set; }
        [JsonProperty("attestationCertificateKeyIdentifiers")]
        public string[] AttestationCertificateKeyIdentifiers { get; set; }
        [JsonProperty("description", Required = Required.Always)]
        public string Description { get; set; }
        [JsonProperty("alternativeDescriptions")]
        public AlternativeDescriptions IETFLanguageCodesMembers { get; set; }
        [JsonProperty("authenticatorVersion", Required = Required.Always)]
        public ushort AuthenticatorVersion { get; set; }
        [JsonProperty("protocolFamily")]
        public string ProtocolFamily { get; set; }
        [JsonProperty("upv", Required = Required.Always)]
        public Version[] Upv { get; set; }
        [JsonProperty("assertionScheme", Required = Required.Always)]
        public string AssertionScheme { get; set; }
        [JsonProperty("authenticationAlgorithm", Required = Required.Always)]
        public ushort AuthenticationAlgorithm { get; set; }
        [JsonProperty("authenticationAlgorithms")]
        public ushort[] AuthenticationAlgorithms { get; set; }
        [JsonProperty("publicKeyAlgAndEncoding", Required = Required.Always)]
        public ushort PublicKeyAlgAndEncoding { get; set; }
        [JsonProperty("publicKeyAlgAndEncodings")]
        public ushort[] PublicKeyAlgAndEncodings { get; set; }
        [JsonProperty("attestationTypes", Required = Required.Always)]
        public ushort[] AttestationTypes { get; set; }
        [JsonProperty("userVerificationDetails", Required = Required.Always)]
        public VerificationMethodDescriptor[][] UserVerificationDetails { get; set; }
        [JsonProperty("keyProtection", Required = Required.Always)]
        public ushort KeyProtection { get; set; }
        [JsonProperty("isKeyRestricted")]
        public bool IsKeyRestricted { get; set; }
        [JsonProperty("isFreshUserVerificationRequired")]
        public bool IsFreshUserVerificationRequired { get; set; }
        [JsonProperty("matcherProtection", Required = Required.Always)]
        public ushort MatcherProtection { get; set; }
        [JsonProperty("cryptoStrength")]
        public ushort CryptoStrength { get; set; }
        [JsonProperty("operatingEnv")]
        public string OperatingEnv { get; set; }
        [JsonProperty("attachmentHint", Required = Required.Always)]
        public ulong AttachmentHint { get; set; }
        [JsonProperty("isSecondFactorOnly", Required = Required.Always)]
        public bool IsSecondFactorOnly { get; set; }
        [JsonProperty("tcDisplay", Required = Required.Always)]
        public ushort TcDisplay { get; set; }
        [JsonProperty("tcDisplayContentType")]
        public string TcDisplayContentType { get; set; }
        [JsonProperty("tcDisplayPNGCharacteristics")]
        public DisplayPNGCharacteristicsDescriptor[] TcDisplayPNGCharacteristics { get; set; }
        [JsonProperty("attestationRootCertificates", Required = Required.Always)]
        public string[] AttestationRootCertificates { get; set; }
        [JsonProperty("ecdaaTrustAnchors")]
        public EcdaaTrustAnchor[] EcdaaTrustAnchors { get; set; }
        [JsonProperty("icon")]
        public string Icon { get; set; }
        [JsonProperty("supportedExtensions")]
        public ExtensionDescriptor[] SupportedExtensions { get; set; }
        public string Hash { get; set; }
    }
    public sealed class MDSMetadata
    {
        private static volatile MDSMetadata mDSMetadata;
        private static object syncRoot = new System.Object();
        public Microsoft.Extensions.Configuration.IConfiguration Configuration { get; }
        public static readonly string mds1url = "https://mds.fidoalliance.org";
        public static readonly string mds2url = "https://mds2.fidoalliance.org";
        public static readonly string tokenParamName = "/?token=";
        private static string _accessToken;
        private static string _cacheDir;
        private string tocAlg;

        private MDSMetadata()
        {
            // Extract app secrets for development
            // https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets?view=aspnetcore-2.1&tabs=windows
            string env = System.Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            if (string.IsNullOrWhiteSpace(env))
            {
                env = "Development";
            }

            var builder = new Microsoft.Extensions.Configuration.ConfigurationBuilder();

            if (env == "Development")
            {
                builder.AddUserSecrets<MDSMetadata>();
            }
            Configuration = builder.Build();

            // We need either an access token or a cache directory, but prefer both
            // If we have only an access token, we can get metadata from directly from MDS and only cache in memory
            // If we have only a cache directory, we can read cached data (as long as it is not expired)
            // If we have both, we can read from either and update cache as necessary
            _accessToken = Configuration["MDSAccessToken"];
            _cacheDir = Configuration["CacheDir"];
            if (0x30 != _accessToken.Length && 3 > _cacheDir.Length) throw new Fido2VerificationException("Either MDSAccessToken or CacheDir is required to instantiate Metadata instance");

            payload = new System.Collections.Generic.Dictionary<System.Guid, MetadataTOCPayloadEntry>();
            // If we have a cache directory, let's try that first
            if (true == System.IO.Directory.Exists(_cacheDir))
            {
                try
                {
                    TOCPayloadFromCache();
                }
                catch (System.Exception ex)
                {
                    if (ex is Fido2VerificationException || ex is System.IO.FileNotFoundException) { }
                    else throw;
                    // Something wrong with cached data, revert to MDS
                }
            }
            // If the payload count is still zero and we have what looks like a good access token, load from MDS
            if (0 == payload.Count && 0x30 == _accessToken.Length)
            {
                TOCPayloadFromURL();
            }
            // If the payload count is zero, we've failed to load metadata
            if (0 == payload.Count) throw new Fido2VerificationException("Failed to load MDS metadata");
        }
        public static MDSMetadata Instance()
        {
            if (null == mDSMetadata)
            {
                lock (syncRoot)
                {
                    if (null == mDSMetadata)
                        mDSMetadata = new MDSMetadata();
                }
            }
            return mDSMetadata;
        }
        public System.Collections.Generic.Dictionary<System.Guid, MetadataTOCPayloadEntry> payload { get; set; }
        private MetadataTOCPayload ValidatedTOCFromJwtSecurityToken(string mdsToc)
        {
            var jwtToken = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(mdsToc);
            tocAlg = jwtToken.Header["alg"] as string;
            var keys = (jwtToken.Header["x5c"] as Newtonsoft.Json.Linq.JArray)
                .Values<string>()
                .Select(x => new ECDsaSecurityKey(
                    (ECDsaCng)(new X509Certificate2(System.Convert.FromBase64String(x)).GetECDsaPublicKey())))
                .ToArray();

            //var client = new System.Net.WebClient();
            //var rootFile = client.DownloadData("https://mds.fidoalliance.org/Root.cer");
            var rootFile =  "MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkG" +
                            "A1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFk" +
                            "YXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoX" +
                            "DTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxs" +
                            "aWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRS" +
                            "b290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+" +
                            "AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4ims" +
                            "rfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYw" +
                            "DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYw" +
                            "HwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAw" +
                            "ZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciW" +
                            "DcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XU" +
                            "YjdBz56jSA==";
            var root = new X509Certificate2(System.Convert.FromBase64String(rootFile));
            /*
            var conformanceRootFile =   "MIICYjCCAeigAwIBAgIPBIdvCXPXJiuD7VW0mgRQMAoGCCqGSM49BAMDMGcxCzAJ" +
                                        "BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF" +
                                        "IE1ldGFkYXRhIFRPQyBTaWduaW5nIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG" +
                                        "QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC" +
                                        "VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh" +
                                        "dGEgVE9DIFNpZ25pbmcgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ" +
                                        "BgcqhkjOPQIBBgUrgQQAIgNiAARcVLd6r4fnNHzs5K2zfbg//4X9/oBqmsdRVtZ9" +
                                        "iXhlgM9vFYaKviYtqmwkq0D3Lihg3qefeZgXXYi4dFgvzU7ZLBapSNM3CT8RDBe/" +
                                        "MBJqsPwaRQbIsGmmItmt/ESNQD6jWjBYMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E" +
                                        "BTADAQH/MBsGA1UdDgQU3feayBzv4V/ToevbM18w9GoZmVkwGwYDVR0jBBTd95rI" +
                                        "HO/hX9Oh69szXzD0ahmZWTAKBggqhkjOPQQDAwNoADBlAjAfT9m8LabIuGS6tXiJ" +
                                        "mRB91SjJ49dk+sPsn+AKx1/PS3wbHEGnGxDIIcQplYDFcXICMQDi33M/oUlb7RDA" +
                                        "mapRBjJxKK+oh7hlSZv4djmZV3YV0JnF1Ed5E4I0f3C04eP0bjw=";
            var conformanceRoot = new X509Certificate2(System.Convert.FromBase64String(conformanceRootFile));
            */
            var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.Add(root);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = keys,
            };
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            SecurityToken validatedToken;

            tokenHandler.ValidateToken(
                mdsToc,
                validationParameters,
                out validatedToken);
            var payload = ((System.IdentityModel.Tokens.Jwt.JwtSecurityToken)validatedToken).Payload.SerializeToJson();
            chain.ChainPolicy.ExtraStore.Add(new X509Certificate2(System.Convert.FromBase64String((jwtToken.Header["x5c"] as Newtonsoft.Json.Linq.JArray).Values<string>().Last())));
            var valid = chain.Build(new X509Certificate2(System.Convert.FromBase64String((jwtToken.Header["x5c"] as Newtonsoft.Json.Linq.JArray).Values<string>().First())));
            // if the root is trusted in the context we are running in, valid should be true here
            if (false == valid)
            {
                // otherwise we have to manually validate that the root in the chain we are testing is the root we downloaded
                if (root.Thumbprint == chain.ChainElements[chain.ChainElements.Count - 1].Certificate.Thumbprint && 
                    // and that the number of elements in the chain accounts for what was in x5c plus the root we added
                    chain.ChainElements.Count == ((jwtToken.Header["x5c"] as Newtonsoft.Json.Linq.JArray).Count + 1) &&
                    // and that the root cert has exactly one status listed against it
                    chain.ChainElements[chain.ChainElements.Count - 1].ChainElementStatus.Length == 1 &&
                    // and that that status is a status of exactly UntrustedRoot
                    chain.ChainElements[chain.ChainElements.Count - 1].ChainElementStatus[0].Status == X509ChainStatusFlags.UntrustedRoot)
                {
                    // if we are good so far, that is a good sign
                    valid = true;
                    for (var i = 0; i < chain.ChainElements.Count - 1; i++)
                    {
                        // check each non-root cert to verify zero status listed against it, otherwise, invalidate chain
                        if (0 != chain.ChainElements[i].ChainElementStatus.Length)
                            valid = false;
                    }
                }
            }
            if (false == valid) throw new Fido2VerificationException("Failed to validate cert chain while parsing TOC");
            return JsonConvert.DeserializeObject<MetadataTOCPayload>(payload);
        }
        private MetadataStatement GetMetadataStatement(MetadataTOCPayloadEntry entry, bool fromCache)
        {
            var rawStatement = "";
            if (false == fromCache)
            {
                var client = new System.Net.WebClient();
                rawStatement = client.DownloadString(entry.Url + tokenParamName + _accessToken);
            }
            if (3 < _cacheDir.Length)
            {
                if (false == System.IO.Directory.Exists(_cacheDir)) System.IO.Directory.CreateDirectory(_cacheDir);
                var filename = _cacheDir + @"\"  + entry.AaGuid + @".jwt";
                if (false == fromCache) System.IO.File.WriteAllText(filename, rawStatement, System.Text.Encoding.UTF8);
                else rawStatement = System.IO.File.ReadAllText(filename);
            }

            var statementBytes = Base64Url.Decode(rawStatement);
            var statement = System.Text.Encoding.UTF8.GetString(statementBytes, 0, statementBytes.Length);
            var ret = JsonConvert.DeserializeObject<MetadataStatement>(statement);
            ret.Hash = Base64Url.Encode(AuthDataHelper.GetHasher(new HashAlgorithmName(tocAlg)).ComputeHash(System.Text.Encoding.UTF8.GetBytes(rawStatement)));
            return ret;
        }
        public void TOCPayloadFromURL()
        {
            var client = new System.Net.WebClient();

            string mdsToc = client.DownloadString(mds2url + tokenParamName + _accessToken);

            if (3 < _cacheDir.Length)
            {
                if (false == System.IO.Directory.Exists(_cacheDir)) System.IO.Directory.CreateDirectory(_cacheDir);
                System.IO.File.WriteAllText(_cacheDir + @"\" + "mdstoc.jwt", mdsToc, System.Text.Encoding.UTF8);
            }

            var metadataTOC = ValidatedTOCFromJwtSecurityToken(mdsToc);

            foreach (var entry in metadataTOC.Entries)
            {
                if (null != entry.AaGuid)
                {
                    entry.MetadataStatement = GetMetadataStatement(entry, false);
                    payload.Add(new System.Guid(entry.AaGuid), entry);
                }
            }
        }
        public void TOCPayloadFromCache()
        {
            var mdsToc = System.IO.File.ReadAllText(_cacheDir + @"\mdstoc.jwt");
            var metadataTOC = ValidatedTOCFromJwtSecurityToken(mdsToc);
            if (System.DateTime.Now > System.DateTime.Parse(metadataTOC.NextUpdate)) throw new Fido2VerificationException("Cached metadataTOC is expired, reload from MDS");
            foreach (var entry in metadataTOC.Entries)
            {
                if (null != entry.AaGuid)
                {
                    entry.MetadataStatement = GetMetadataStatement(entry, true);
                    payload.Add(new System.Guid(entry.AaGuid), entry);
                }
            }
            
            CustomTOCPayloadFromCache();
        }
        public void CustomTOCPayloadFromCache()
        {
            if (true == System.IO.Directory.Exists(_cacheDir + @"\Custom"))
            {
                foreach (string filename in System.IO.Directory.GetFiles(_cacheDir + @"\Custom"))
                {
                    var rawStatement = System.IO.File.ReadAllText(filename);
                    var statement = JsonConvert.DeserializeObject<MetadataStatement>(rawStatement);
                    var entry = new MetadataTOCPayloadEntry();
                    entry.AaGuid = statement.AaGuid;
                    entry.MetadataStatement = statement;
                    if (null != entry.AaGuid) payload.Add(new System.Guid(entry.AaGuid), entry);
                }
            }
        }
    }
}
