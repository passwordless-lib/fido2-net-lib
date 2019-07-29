﻿using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace Fido2NetLib
{
   

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

    

    public class Version
    {
        [JsonProperty("major")]
        public ushort Major { get; set; }
        [JsonProperty("minor")]
        public ushort Minor { get; set; }
    }
 
   

    public class VerificationMethodANDCombinations
    {
        [JsonProperty("verificationMethodANDCombinations")]
        public VerificationMethodDescriptor[] VerificationMethodAndCombinations { get; set; }
    }
  
    
   
   

    

    public sealed class MDSMetadata : IMetadataService
    {
        private static volatile MDSMetadata mDSMetadata;
        private static volatile MDSMetadata ConformanceMetadata;
        private static object syncRoot = new object();
        private static readonly string mds2url = "https://mds2.fidoalliance.org";
        private static readonly string tokenParamName = "/?token=";
        private static string _accessToken;
        private static string _cacheDir;
        private static string _origin;
        private bool tOCReady;
        private bool conformanceTOCReady;
        private DateTime nextTOCUpdate;
        private string tocAlg;
        private static HttpClient _httpClient;
        // Sample bogus key from https://fidoalliance.org/metadata/
        private static readonly string _invalidToken = "6d6b44d78b09fed0c5559e34c71db291d0d322d4d4de0000";
        private MDSMetadata(string accessToken, string cachedirPath, HttpClient httpClient = null)
        {
            // We need either an access token or a cache directory, but prefer both
            if (null == accessToken && null == cachedirPath)
            {
                Trace.TraceWarning("MetadataService was not given accessToken and cacheDirPath and cannot be used.");
                return;
            };

            Trace.TraceInformation($"MetadataService started with acccessToken and CacheDirpath: {cachedirPath}");

            // If we have only an access token, we can get metadata from directly from MDS and only cache in memory
            // If we have only a cache directory, we can read cached data (as long as it is not expired)
            // If we have both, we can read from either and update cache as necessary
            _accessToken = accessToken;
            _cacheDir = cachedirPath;
            _httpClient = httpClient ?? new HttpClient();
            if (null != _accessToken && 0x30 != _accessToken.Length && null != _cacheDir && 3 > _cacheDir.Length) throw new Fido2VerificationException("Either MDSAccessToken or CacheDir is required to instantiate Metadata instance");

            payload = new System.Collections.Generic.Dictionary<Guid, MetadataTOCPayloadEntry>();
        }
        /// <summary>
        /// Returns or creates an instance of the MetadataSerivce. The paramters will only be used when the singleton is not already created.
        /// </summary>
        /// <param name="accesskey"></param>
        /// <param name="cachedirPath"></param>
        /// <returns></returns>
        public static IMetadataService Instance(string accesskey, string cachedirPath, HttpClient httpClient = null)
        {
            if (null == mDSMetadata)
            {
                lock (syncRoot)
                {
                    if (null == mDSMetadata)
                    {
                        mDSMetadata = new MDSMetadata(accesskey, cachedirPath, httpClient);
                    }
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
        public static IMetadataService ConformanceInstance(string accesskey, string cachedirPath, string origin, HttpClient httpClient = null)
        {
            if (null == ConformanceMetadata)
            {
                lock (syncRoot)
                {
                    if (null == ConformanceMetadata)
                    {
                        _origin = origin;
                        ConformanceMetadata = new MDSMetadata(accesskey, cachedirPath, httpClient);
                    }
                }
            }
            return ConformanceMetadata;
        }

        public System.Collections.Generic.Dictionary<Guid, MetadataTOCPayloadEntry> payload { get; set; }
        private async Task<MetadataTOCPayload> ValidatedTOCFromJwtSecurityToken(string mdsToc)
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
            var rootFile = "MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkG" +
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


            var conformanceRootFile = "MIICYjCCAeigAwIBAgIPBIdvCXPXJiuD7VW0mgRQMAoGCCqGSM49BAMDMGcxCzAJ" +
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

            var root = ConformanceTesting() ? new X509Certificate2(Convert.FromBase64String(conformanceRootFile)) : new X509Certificate2(Convert.FromBase64String(rootFile));

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
                foreach (var element in chain.ChainElements)
                {
                    if (element.Certificate.Issuer != element.Certificate.Subject)
                    {
                        var cdp = CryptoUtils.CDPFromCertificateExts(element.Certificate.Extensions);
                        var crlFile = await DownloadData(cdp);
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
        private async Task<MetadataStatement> GetMetadataStatement(MetadataTOCPayloadEntry entry, bool fromCache)
        {
            var rawStatement = "";
            if (false == fromCache)
            {
                rawStatement = await DownloadString(entry.Url + tokenParamName + _accessToken);
            }
            if (null != _cacheDir && 3 < _cacheDir.Length)
            {
                if (false == System.IO.Directory.Exists(_cacheDir)) System.IO.Directory.CreateDirectory(_cacheDir);
                var filename = _cacheDir + @"\" + entry.AaGuid + @".jwt";
                if (false == fromCache) System.IO.File.WriteAllText(filename, rawStatement, System.Text.Encoding.UTF8);
                else rawStatement = System.IO.File.ReadAllText(filename);
            }

            var statementBytes = Base64Url.Decode(rawStatement);
            var statement = System.Text.Encoding.UTF8.GetString(statementBytes, 0, statementBytes.Length);
            var ret = JsonConvert.DeserializeObject<MetadataStatement>(statement);
            ret.Hash = Base64Url.Encode(CryptoUtils.GetHasher(new HashAlgorithmName(tocAlg)).ComputeHash(System.Text.Encoding.UTF8.GetBytes(rawStatement)));
            return ret;
        }
        public async Task GetTOCPayload(bool fromCache)
        {
            var mdsToc = "";
            if (false == fromCache)
            {
                mdsToc = await DownloadString(mds2url + tokenParamName + _accessToken);
                if (null != _cacheDir && 3 < _cacheDir.Length)
                {
                    if (false == System.IO.Directory.Exists(_cacheDir)) System.IO.Directory.CreateDirectory(_cacheDir);
                    System.IO.File.WriteAllText(_cacheDir + @"\" + "mdstoc.jwt", mdsToc, System.Text.Encoding.UTF8);
                }
            }
            else mdsToc = System.IO.File.ReadAllText(_cacheDir + @"\mdstoc.jwt");

            var metadataTOC = await ValidatedTOCFromJwtSecurityToken(mdsToc);

            nextTOCUpdate = DateTime.Parse(metadataTOC.NextUpdate);
            if (true == fromCache && DateTime.Now > nextTOCUpdate) throw new Fido2VerificationException("Cached metadataTOC is expired, reload from MDS");

            foreach (var entry in metadataTOC.Entries)
            {
                if (null != entry.AaGuid)
                {
                    entry.MetadataStatement = await GetMetadataStatement(entry, fromCache);
                    payload.Add(new Guid(entry.AaGuid), entry);
                }
            }
            if (true == fromCache) await CustomTOCPayloadFromCache();
        }

        public static async Task<string> DownloadString(string url)
        {
            return await _httpClient.GetStringAsync(url);
        }
        public static async Task<byte[]> DownloadData(string url)
        {
            return await _httpClient.GetByteArrayAsync(url);
        }
        public async Task AddMDSTOC()
        {
            tOCReady = false;
            // If we have a cache directory, let's try that first
            if (true == System.IO.Directory.Exists(_cacheDir))
            {
                try
                {
                    await GetTOCPayload(true);
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
                await GetTOCPayload(false);
            }
            // If the payload count is zero, we've failed to load metadata
            if (0 == payload.Count) throw new Fido2VerificationException("Failed to load MDS metadata");
            else tOCReady = true;
        }
        private async Task ProcessConformanceTOC(string tocURL)
        {
            var rawTOC = await DownloadString(tocURL);
            MetadataTOCPayload toc = null;
            try { toc = await ValidatedTOCFromJwtSecurityToken(rawTOC); }

            catch { return; }

            foreach (var entry in toc.Entries)
            {
                if (null != entry.AaGuid)
                {
                    var rawStatement = await DownloadString(entry.Url);
                    var statementBytes = Base64Url.Decode(rawStatement);
                    var statement = System.Text.Encoding.UTF8.GetString(statementBytes, 0, statementBytes.Length);
                    var metadataStatement = JsonConvert.DeserializeObject<MetadataStatement>(statement);
                    metadataStatement.Hash = Base64Url.Encode(CryptoUtils.GetHasher(new HashAlgorithmName(tocAlg)).ComputeHash(System.Text.Encoding.UTF8.GetBytes(rawStatement)));
                    entry.MetadataStatement = metadataStatement;
                    payload.Add(new Guid(entry.AaGuid), entry);
                }
            }
        }
        public async Task AddConformanceTOC()
        {
            conformanceTOCReady = false;
            var req = new
            {
                endpoint = _origin
            };
            var content = new StringContent(JsonConvert.SerializeObject(req), System.Text.Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("https://fidoalliance.co.nz/mds/getEndpoints", content);
            var result = JsonConvert.DeserializeObject<MDSGetEndpointResponse>(await response.Content.ReadAsStringAsync());
            var conformanceEndpoints = new System.Collections.Generic.List<string>(result.Result);
            var tocURLTasks = from tocURL in conformanceEndpoints select ProcessConformanceTOC(tocURL);
            await Task.WhenAll(tocURLTasks.ToArray());
            await CustomTOCPayloadFromCache();
            conformanceTOCReady = true;
        }
        public async Task CustomTOCPayloadFromCache()
        {
            if (true == ConformanceTesting() && true == System.IO.Directory.Exists(_cacheDir + @"\Conformance"))
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
                var yubicoRoot = "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ" +
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
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Windows Hello software authenticator" }
                };
                payload.Add(new Guid(msftWhfbSoftware.AaGuid), msftWhfbSoftware);
                var msftWhfbSoftwareVbs = new MetadataTOCPayloadEntry
                {
                    AaGuid = "6E96969E-A5CF-4AAD-9B56-305FE6C82795",
                    Hash = "",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Windows Hello VBS software authenticator" }
                };
                payload.Add(new Guid(msftWhfbSoftwareVbs.AaGuid), msftWhfbSoftwareVbs);
                var msftWhfbHardware = new MetadataTOCPayloadEntry
                {
                    AaGuid = "08987058-CADC-4B81-B6E1-30DE50DCBE96",
                    Hash = "",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Windows Hello hardware authenticator" }
                };
                payload.Add(new Guid(msftWhfbHardware.AaGuid), msftWhfbHardware);
                var msftWhfbHardwareVbs = new MetadataTOCPayloadEntry
                {
                    AaGuid = "9DDD1817-AF5A-4672-A2B9-3E3DD95000A9",
                    Hash = "",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = new MetadataStatement() { AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL }, Hash = "", Description = "Windows Hello VBS hardware authenticator" }
                };
                payload.Add(new Guid(msftWhfbHardwareVbs.AaGuid), msftWhfbHardwareVbs);

                var solostatement = await DownloadString("https://raw.githubusercontent.com/solokeys/solo/master/metadata/Solo-FIDO2-CTAP2-Authenticator.json");
                var soloMetadataStatement = JsonConvert.DeserializeObject<MetadataStatement>(solostatement);
                var soloKeysSolo = new MetadataTOCPayloadEntry
                {
                    AaGuid = soloMetadataStatement.AaGuid,
                    Url = "https://raw.githubusercontent.com/solokeys/solo/master/metadata/Solo-FIDO2-CTAP2-Authenticator.json",
                    StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                    MetadataStatement = soloMetadataStatement
                };
                payload.Add(new Guid(soloKeysSolo.AaGuid), soloKeysSolo);
            }
        }

        public MetadataTOCPayloadEntry GetEntry(Guid aaguid)
        {
            MetadataTOCPayloadEntry entry;
            if (true == ConformanceTesting())
            {
                ConformanceMetadata.payload.TryGetValue(aaguid, out entry);
            }
            else
            {
                mDSMetadata.payload.TryGetValue(aaguid, out entry);
            }
            return entry;
        }
        public bool ConformanceTesting()
        {
            return (0 == _accessToken.CompareTo(_invalidToken));
        }
        public bool IsInitialized()
        {
            return ConformanceTesting() ? conformanceTOCReady : tOCReady;
        }
        public async Task Initialize()
        {
            if (true == ConformanceTesting())
                await AddConformanceTOC();
            else await AddMDSTOC();
        }
    }
}
