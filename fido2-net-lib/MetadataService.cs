using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

    public interface IMetadataService
    {
        MetadataTOCPayloadEntry GetEntry(Guid aaguid);
        bool ConformanceTesting();
    }

    public sealed class MDSMetadata : IMetadataService
    {
        private static volatile MDSMetadata mDSMetadata;
        private static volatile MDSMetadata ConformanceMetadata;
        private static object syncRoot = new object();
        public static readonly string mds2url = "https://mds2.fidoalliance.org";
        public static readonly string tokenParamName = "/?token=";
        private static string _accessToken;
        private static string _cacheDir;
        private static string[] _endpoints;
        private string tocAlg;
        public readonly bool conformance = false;

        private MDSMetadata(string accessToken, string cachedirPath)
        {
            // We need either an access token or a cache directory, but prefer both
            if (null == accessToken && null == cachedirPath) return;
            
            // If we have only an access token, we can get metadata from directly from MDS and only cache in memory
            // If we have only a cache directory, we can read cached data (as long as it is not expired)
            // If we have both, we can read from either and update cache as necessary
            _accessToken = accessToken;
            _cacheDir = cachedirPath;
            if (null != _accessToken && 0x30 != _accessToken.Length && null != _cacheDir && 3 > _cacheDir.Length) throw new Fido2VerificationException("Either MDSAccessToken or CacheDir is required to instantiate Metadata instance");
            
            // Sample bogus key from https://fidoalliance.org/metadata/
            var invalidToken = "6d6b44d78b09fed0c5559e34c71db291d0d322d4d4de0000";
            if (_accessToken == invalidToken) conformance = true;

            payload = new System.Collections.Generic.Dictionary<Guid, MetadataTOCPayloadEntry>();

            if (false == conformance)
            {
                // If we have a cache directory, let's try that first
                if (true == System.IO.Directory.Exists(_cacheDir))
                {
                    try
                    {
                        GetTOCPayload(true);
                    }
                    catch (Exception ex)
                    {
                        if (ex is Fido2VerificationException || ex is System.IO.FileNotFoundException) { }
                        else throw;
                        // Something wrong with cached data, revert to MDS
                    }
                }
                // If the payload count is still zero and we have what looks like a good access token, load from MDS
                if (0 == payload.Count && null != _accessToken && 0x30 == _accessToken.Length)
                {
                    GetTOCPayload(false);
                }
                // If the payload count is zero, we've failed to load metadata
                if (0 == payload.Count) throw new Fido2VerificationException("Failed to load MDS metadata");
            }
            else AddConformanceTOC();
        }
        /// <summary>
        /// Returns or creates an instance of the MetadataSerivce. The paramters will only be used when the singleton is not already created.
        /// </summary>
        /// <param name="accesskey"></param>
        /// <param name="cachedirPath"></param>
        /// <returns></returns>
        public static IMetadataService Instance(string accesskey, string cachedirPath)
        {
            if (null == mDSMetadata)
            {
                lock (syncRoot)
                {
                    if (null == mDSMetadata)
                        mDSMetadata = new MDSMetadata(accesskey, cachedirPath);
                }
            }
            return mDSMetadata;
        }
        public class MDSGetEndpointResponse
        {
            [JsonProperty("status", Required = Required.Always)]
            public string Status { get; set; }
            [JsonProperty("result", Required = Required.Always)]
            public string[] Result { get; set; }
        }
        public static IMetadataService ConformanceInstance(string accesskey, string cachedirPath, string origin)
        {
            if (null == ConformanceMetadata)
            {
                lock (syncRoot)
                {
                    if (null == ConformanceMetadata)
                    {
                        var httpWebRequest = (System.Net.HttpWebRequest)System.Net.WebRequest.Create("https://fidoalliance.co.nz/mds/getEndpoints");
                        httpWebRequest.ContentType = "application/json";
                        httpWebRequest.Method = "POST";

                        using (var sw = new System.IO.StreamWriter(httpWebRequest.GetRequestStream()))
                        {
                            var req = new
                            {
                                endpoint = origin
                            };

                            sw.Write(JsonConvert.SerializeObject(req));
                            sw.Flush();
                            sw.Close();
                        }

                        var httpResponse = (System.Net.HttpWebResponse)httpWebRequest.GetResponse();

                        using (var sr = new System.IO.StreamReader(httpResponse.GetResponseStream()))
                        {
                            var response = JsonConvert.DeserializeObject<MDSGetEndpointResponse>(sr.ReadToEnd());
                            _endpoints = response.Result;
                        }

                        ConformanceMetadata = new MDSMetadata(accesskey, cachedirPath);
                    }
                }
            }
            return ConformanceMetadata;
        }

        public System.Collections.Generic.Dictionary<Guid, MetadataTOCPayloadEntry> payload { get; set; }
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

            var root = conformance ? new X509Certificate2(Convert.FromBase64String(conformanceRootFile)) : new X509Certificate2(Convert.FromBase64String(rootFile));

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

            tokenHandler.ValidateToken(
                mdsToc,
                validationParameters,
                out var validatedToken);
            var payload = ((System.IdentityModel.Tokens.Jwt.JwtSecurityToken)validatedToken).Payload.SerializeToJson();
            chain.ChainPolicy.ExtraStore.Add(new X509Certificate2(System.Convert.FromBase64String((jwtToken.Header["x5c"] as Newtonsoft.Json.Linq.JArray).Values<string>().Last())));
            var valid = chain.Build(new X509Certificate2(System.Convert.FromBase64String((jwtToken.Header["x5c"] as Newtonsoft.Json.Linq.JArray).Values<string>().First())));
            // if the root is trusted in the context we are running in, valid should be true here
            if (false == valid)
            {
                var client = new System.Net.WebClient();
                foreach (var element in chain.ChainElements)
                {
                    if (element.Certificate.Issuer != element.Certificate.Subject)
                    {
                        var cdp = CryptoUtils.CDPFromCertificateExts(element.Certificate.Extensions);
                        var crlFile = client.DownloadData(cdp);
                        if (true == CryptoUtils.IsCertInCRL(crlFile, element.Certificate)) throw new Fido2VerificationException(string.Format("Cert {0} found in CRL {1}", element.Certificate.Subject, cdp));
                    }
                }

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
            if (null != _cacheDir && 3 < _cacheDir.Length)
            {
                if (false == System.IO.Directory.Exists(_cacheDir)) System.IO.Directory.CreateDirectory(_cacheDir);
                var filename = _cacheDir + @"\"  + entry.AaGuid + @".jwt";
                if (false == fromCache) System.IO.File.WriteAllText(filename, rawStatement, System.Text.Encoding.UTF8);
                else rawStatement = System.IO.File.ReadAllText(filename);
            }

            var statementBytes = Base64Url.Decode(rawStatement);
            var statement = System.Text.Encoding.UTF8.GetString(statementBytes, 0, statementBytes.Length);
            var ret = JsonConvert.DeserializeObject<MetadataStatement>(statement);
            ret.Hash = Base64Url.Encode(CryptoUtils.GetHasher(new HashAlgorithmName(tocAlg)).ComputeHash(System.Text.Encoding.UTF8.GetBytes(rawStatement)));
            return ret;
        }
        public void GetTOCPayload(bool fromCache)
        {
            var client = new System.Net.WebClient();
            var mdsToc = "";
            if (false == fromCache)
            {
                mdsToc = client.DownloadString(mds2url + tokenParamName + _accessToken);
                if (null != _cacheDir && 3 < _cacheDir.Length)
                {
                    if (false == System.IO.Directory.Exists(_cacheDir)) System.IO.Directory.CreateDirectory(_cacheDir);
                    System.IO.File.WriteAllText(_cacheDir + @"\" + "mdstoc.jwt", mdsToc, System.Text.Encoding.UTF8);
                }
            }
            else mdsToc = System.IO.File.ReadAllText(_cacheDir + @"\mdstoc.jwt");

            var metadataTOC = ValidatedTOCFromJwtSecurityToken(mdsToc);

            if (true == fromCache && System.DateTime.Now > System.DateTime.Parse(metadataTOC.NextUpdate)) throw new Fido2VerificationException("Cached metadataTOC is expired, reload from MDS");

            foreach (var entry in metadataTOC.Entries)
            {
                if (null != entry.AaGuid)
                {
                    entry.MetadataStatement = GetMetadataStatement(entry, fromCache);
                    payload.Add(new Guid(entry.AaGuid), entry);
                }
            }
            if (true == fromCache) CustomTOCPayloadFromCache();
        }

        public void AddConformanceTOC()
        {
            var client = new System.Net.WebClient();
            foreach (var tocURL in _endpoints)
            {
                var rawTOC = client.DownloadString(tocURL);
                MetadataTOCPayload toc = null;
                try { toc = ValidatedTOCFromJwtSecurityToken(rawTOC); }
                catch { continue; }
                
                foreach (var entry in toc.Entries)
                {
                    if (null != entry.AaGuid)
                    {
                        var rawStatement = client.DownloadString(entry.Url);
                        var statementBytes = Base64Url.Decode(rawStatement);
                        var statement = System.Text.Encoding.UTF8.GetString(statementBytes, 0, statementBytes.Length);
                        var metadataStatement = JsonConvert.DeserializeObject<MetadataStatement>(statement);
                        metadataStatement.Hash = Base64Url.Encode(CryptoUtils.GetHasher(new HashAlgorithmName(tocAlg)).ComputeHash(System.Text.Encoding.UTF8.GetBytes(rawStatement)));
                        entry.MetadataStatement = metadataStatement;
                        payload.Add(new Guid(entry.AaGuid), entry);
                    }
                }
            }
            CustomTOCPayloadFromCache();
        }
        public void CustomTOCPayloadFromCache()
        {
            if (true == conformance && true == System.IO.Directory.Exists(_cacheDir + @"\Conformance"))
            {
                foreach (var filename in System.IO.Directory.GetFiles(_cacheDir + @"\Conformance"))
                {
                    var rawStatement = System.IO.File.ReadAllText(filename);
                    var statement = JsonConvert.DeserializeObject<MetadataStatement>(rawStatement);
                    var conformanceEntry = new MetadataTOCPayloadEntry
                    {
                        AaGuid = statement.AaGuid,
                        MetadataStatement = statement,
                        StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } }
                    };
                    if (null != conformanceEntry.AaGuid) payload.Add(new Guid(conformanceEntry.AaGuid), conformanceEntry);
                }
            }
            else
            {
                if (true == System.IO.Directory.Exists(_cacheDir + @"\Custom"))
                {
                    foreach (var filename in System.IO.Directory.GetFiles(_cacheDir + @"\Custom"))
                    {
                        var rawStatement = System.IO.File.ReadAllText(filename);
                        var statement = JsonConvert.DeserializeObject<MetadataStatement>(rawStatement);
                        var entry = new MetadataTOCPayloadEntry
                        {
                            AaGuid = statement.AaGuid,
                            MetadataStatement = statement,
                            StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } }
                        };
                        if (null != entry.AaGuid) payload.Add(new Guid(entry.AaGuid), entry);
                    }
                }

                // from https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt
                var yubicoRoot =    "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ" +
                                    "dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw" +
                                    "MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290" +
                                    "IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK" +
                                    "AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk" +
                                    "5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep" +
                                    "8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw" +
                                    "nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT" +
                                    "9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw" +
                                    "LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ" +
                                    "hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN" +
                                    "BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4" +
                                    "MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt" +
                                    "hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k" +
                                    "LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U" +
                                    "sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc" +
                                    "U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==";

                var yubico = new MetadataTOCPayloadEntry
                {
                    AaGuid = "f8a011f3-8c0a-4d15-8006-17111f9edc7d",
                    Hash = "",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Yubico YubiKey FIDO2", AttestationRootCertificates = new string[] { yubicoRoot } }
                };
                payload.Add(new Guid(yubico.AaGuid), yubico);

                // YubiKey 5 USB and NFC AAGUID values from https://support.yubico.com/support/solutions/articles/15000014219-yubikey-5-series-technical-manual#AAGUID_Valuesxf002do
                var yubikey5usb = new MetadataTOCPayloadEntry
                {
                    AaGuid = "cb69481e-8ff7-4039-93ec-0a2729a154a8",
                    Hash = "",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Yubico YubiKey 5 USB", AttestationRootCertificates = new string[] { yubicoRoot } }
                };
                payload.Add(new Guid(yubikey5usb.AaGuid), yubikey5usb);

                var yubikey5nfc = new MetadataTOCPayloadEntry
                {
                    AaGuid = "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
                    Hash = "",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Yubico YubiKey 5 NFC", AttestationRootCertificates = new string[] { yubicoRoot } }
                };
                payload.Add(new Guid(yubikey5nfc.AaGuid), yubikey5nfc);

                var msftWhfbSoftware = new MetadataTOCPayloadEntry
                {
                    AaGuid = "6028B017-B1D4-4C02-B4B3-AFCDAFC96BB2",
                    Hash = "",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Windows Hello software authenticator"}
                };
                payload.Add(new Guid(msftWhfbSoftware.AaGuid), msftWhfbSoftware);
                var msftWhfbSoftwareVbs = new MetadataTOCPayloadEntry
                {
                    AaGuid = "6E96969E-A5CF-4AAD-9B56-305FE6C82795",
                    Hash = "",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Windows Hello VBS software authenticator"}
                };
                payload.Add(new Guid(msftWhfbSoftwareVbs.AaGuid), msftWhfbSoftwareVbs);
                var msftWhfbHardware = new MetadataTOCPayloadEntry
                {
                    AaGuid = "08987058-CADC-4B81-B6E1-30DE50DCBE96",
                    Hash = "",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Windows Hello hardware authenticator"}
                };
                payload.Add(new Guid(msftWhfbHardware.AaGuid), msftWhfbHardware);
                var msftWhfbHardwareVbs = new MetadataTOCPayloadEntry
                {
                    AaGuid = "9DDD1817-AF5A-4672-A2B9-3E3DD95000A9",
                    Hash = "",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Windows Hello VBS hardware authenticator"}
                };
                payload.Add(new Guid(msftWhfbHardwareVbs.AaGuid), msftWhfbHardwareVbs);

                var client = new System.Net.WebClient();
                var solostatement = client.DownloadString("https://raw.githubusercontent.com/solokeys/solo/master/metadata/solo-FIDO2-CTAP2-Authenticator.json");
                var soloMetadataStatement = JsonConvert.DeserializeObject<MetadataStatement>(solostatement);
                var soloKeysSolo = new MetadataTOCPayloadEntry
                {
                    AaGuid = soloMetadataStatement.AaGuid,
                    Url = "https://raw.githubusercontent.com/solokeys/solo/master/metadata/solo-FIDO2-CTAP2-Authenticator.json",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = soloMetadataStatement
                };
                payload.Add(new Guid(soloKeysSolo.AaGuid), soloKeysSolo);
            }
        }

        public MetadataTOCPayloadEntry GetEntry(Guid aaguid)
        {
            MetadataTOCPayloadEntry entry;
            if (true == conformance)
                ConformanceMetadata.payload.TryGetValue(aaguid, out entry);

            else mDSMetadata.payload.TryGetValue(aaguid, out entry);
            return entry;
        }
        public bool ConformanceTesting()
        {
            return conformance;
        }
    }
}
