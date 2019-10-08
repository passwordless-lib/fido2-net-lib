using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Fido2NetLib
{
    internal class MDSGetEndpointResponse
    {
        [JsonProperty("status", Required = Required.Always)]
        public string Status { get; set; }
        [JsonProperty("result", Required = Required.Always)]
        public string[] Result { get; set; }
    }

    public class ConformanceMetadataRepository : IMetadataRepository
    {
        protected const string ROOT_CERT = "MIICYjCCAeigAwIBAgIPBIdvCXPXJiuD7VW0mgRQMAoGCCqGSM49BAMDMGcxCzAJ" +
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

        protected readonly string _tocUrl;
        protected readonly HttpClient _httpClient;

        protected string _tocAlg;

        private readonly string _origin = "http://localhost";

        private readonly string _getEndpointsUrl = "https://fidoalliance.co.nz/mds/getEndpoints";

        public ConformanceMetadataRepository(HttpClient client, string origin)
        {
            _httpClient = client ?? new HttpClient();
            _origin = origin;
        }

        private Task<string> GetTocAlg()
        {
            if (!string.IsNullOrEmpty(_tocAlg))
            {
                return Task.FromResult(_tocAlg);
            }
            throw new InvalidOperationException("Could not determine TOC algorith.");
        }

        public async Task<MetadataStatement> GetMetadataStatement(MetadataTOCPayloadEntry entry)
        {
            var statementBase64Url = await DownloadStringAsync(entry.Url);
            var tocAlg = await GetTocAlg();

            var statementBytes = Base64Url.Decode(statementBase64Url);
            var statementString = Encoding.UTF8.GetString(statementBytes, 0, statementBytes.Length);
            var statement = JsonConvert.DeserializeObject<MetadataStatement>(statementString);
            using(HashAlgorithm hasher = CryptoUtils.GetHasher(new HashAlgorithmName(tocAlg)))
            {
                statement.Hash = Base64Url.Encode(hasher.ComputeHash(Encoding.UTF8.GetBytes(statementBase64Url)));
            }

            return statement;
        }

        public async Task<MetadataTOCPayload> GetToc()
        {
            var req = new
            {
                endpoint = _origin
            };

            var content = new StringContent(JsonConvert.SerializeObject(req), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync(_getEndpointsUrl, content);
            var result = JsonConvert.DeserializeObject<MDSGetEndpointResponse>(await response.Content.ReadAsStringAsync());
            var conformanceEndpoints = new List<string>(result.Result);

            var combinedToc = new MetadataTOCPayload
            {
                Number = -1,
                NextUpdate = "2099-08-07"
            };

            var entries = new List<MetadataTOCPayloadEntry>();

            foreach(var tocUrl in conformanceEndpoints)
            {
                var rawToc = await DownloadStringAsync(tocUrl);

                MetadataTOCPayload toc = null;

                try
                {
                    toc = await DeserializeAndValidateToc(rawToc);
                }
                catch
                {
                    continue;
                }
                
                if(string.Compare(toc.NextUpdate, combinedToc.NextUpdate) < 0)
                    combinedToc.NextUpdate = toc.NextUpdate;
                if (combinedToc.Number < toc.Number)
                    combinedToc.Number = toc.Number;

                foreach (var entry in toc.Entries)
                {
                    entries.Add(entry);
                }
            }

            combinedToc.Entries = entries.ToArray();
            return combinedToc;
        }

        protected async Task<string> DownloadStringAsync(string url)
        {
            return await _httpClient.GetStringAsync(url);
        }

        protected async Task<byte[]> DownloadDataAsync(string url)
        {
            return await _httpClient.GetByteArrayAsync(url);
        }

        public async Task<MetadataTOCPayload> DeserializeAndValidateToc(string toc)
        {
            var jwtToken = new JwtSecurityToken(toc);
            _tocAlg = jwtToken.Header["alg"] as string;

            var keys = new List<SecurityKey>();

            var keyStrings = (jwtToken.Header["x5c"] as JArray).Values<string>();

            foreach(var keyString in keyStrings)
            {
                var cert = new X509Certificate2(Convert.FromBase64String(keyString));
                var ecdsaPublicKey = cert.GetECDsaPublicKey();
                if(ecdsaPublicKey != null)
                {
                    keys.Add(new ECDsaSecurityKey(ecdsaPublicKey));
                }

                var rsa = cert.GetRSAPublicKey();
                if(rsa != null)
                {
                    keys.Add(new RsaSecurityKey(rsa));
                }
            }
 
            var root = new X509Certificate2(Convert.FromBase64String(ROOT_CERT));

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

            var tokenHandler = new JwtSecurityTokenHandler();

            tokenHandler.ValidateToken(
                toc,
                validationParameters,
                out var validatedToken);

            var payload = ((JwtSecurityToken)validatedToken).Payload.SerializeToJson();

            chain.ChainPolicy.ExtraStore.Add(new X509Certificate2(Convert.FromBase64String((jwtToken.Header["x5c"] as JArray).Values<string>().Last())));

            var valid = chain.Build(new X509Certificate2(Convert.FromBase64String((jwtToken.Header["x5c"] as JArray).Values<string>().First())));
            // if the root is trusted in the context we are running in, valid should be true here
            if (!valid)
            {
                foreach (var element in chain.ChainElements)
                {
                    if (element.Certificate.Issuer != element.Certificate.Subject)
                    {
                        var cdp = CryptoUtils.CDPFromCertificateExts(element.Certificate.Extensions);
                        var crlFile = await DownloadDataAsync(cdp);
                        if (true == CryptoUtils.IsCertInCRL(crlFile, element.Certificate))
                            throw new Fido2VerificationException(string.Format("Cert {0} found in CRL {1}", element.Certificate.Subject, cdp));
                    }
                }

                // otherwise we have to manually validate that the root in the chain we are testing is the root we downloaded
                if (root.Thumbprint == chain.ChainElements[chain.ChainElements.Count - 1].Certificate.Thumbprint &&
                    // and that the number of elements in the chain accounts for what was in x5c plus the root we added
                    chain.ChainElements.Count == ((jwtToken.Header["x5c"] as JArray).Count + 1) &&
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

            if (!valid)
                throw new Fido2VerificationException("Failed to validate cert chain while parsing TOC");

            return JsonConvert.DeserializeObject<MetadataTOCPayload>(payload);
        }
    }
}
