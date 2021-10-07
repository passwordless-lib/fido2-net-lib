using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Json.Linq;
using Newtonsoft.Json.Linq;

namespace Fido2NetLib
{
   
    public class ConformanceMetadataRepository : IMetadataRepository
    {
        protected const string ROOT_CERT = "MIICaDCCAe6gAwIBAgIPBCqih0DiJLW7+UHXx/o1MAoGCCqGSM49BAMDMGcxCzAJ" +
                                        "BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF" +
                                        "IE1ldGFkYXRhIDMgQkxPQiBST09UIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG" +
                                        "QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC" +
                                        "VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh" +
                                        "dGEgMyBCTE9CIFJPT1QgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ" +
                                        "BgcqhkjOPQIBBgUrgQQAIgNiAASKYiz3YltC6+lmxhPKwA1WFZlIqnX8yL5RybSL" +
                                        "TKFAPEQeTD9O6mOz+tg8wcSdnVxHzwnXiQKJwhrav70rKc2ierQi/4QUrdsPes8T" +
                                        "EirZOkCVJurpDFbXZOgs++pa4XmjYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E" +
                                        "BTADAQH/MB0GA1UdDgQWBBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAfBgNVHSMEGDAW" +
                                        "gBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAKBggqhkjOPQQDAwNoADBlAjEA/xFsgri0" +
                                        "xubSa3y3v5ormpPqCwfqn9s0MLBAtzCIgxQ/zkzPKctkiwoPtDzI51KnAjAmeMyg" +
                                        "X2S5Ht8+e+EQnezLJBJXtnkRWY+Zt491wgt/AwSs5PHHMv5QgjELOuMxQBc=";

        protected readonly string _blobUrl;
        protected readonly HttpClient _httpClient;

        private readonly string _origin = "http://localhost";

        private readonly string _getEndpointsUrl = "https://mds3.certinfra.fidoalliance.org/getEndpoints";

        public ConformanceMetadataRepository(HttpClient client, string origin)
        {
            _httpClient = client ?? new HttpClient();
            _origin = origin;
        }

        public async Task<MetadataStatement> GetMetadataStatement(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry)
        {
            return entry.MetadataStatement;
        }

        public async Task<MetadataBLOBPayload> GetBLOB()
        {
            var req = new
            {
                endpoint = _origin
            };

            var content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(req), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync(_getEndpointsUrl, content);
            var result = Newtonsoft.Json.JsonConvert.DeserializeObject<MDSGetEndpointResponse>(await response.Content.ReadAsStringAsync());
            var conformanceEndpoints = new List<string>(result.Result);

            var combinedBlob = new MetadataBLOBPayload
            {
                Number = -1,
                NextUpdate = "2099-08-07"
            };

            var entries = new List<MetadataBLOBPayloadEntry>();

            foreach(var BLOBUrl in conformanceEndpoints)
            {
                var rawBlob = await DownloadStringAsync(BLOBUrl);

                MetadataBLOBPayload blob = null;

                try
                {
                    blob = await DeserializeAndValidateBlob(rawBlob);
                }
                catch
                {
                    continue;
                }
                
                if(string.Compare(blob.NextUpdate, combinedBlob.NextUpdate) < 0)
                    combinedBlob.NextUpdate = blob.NextUpdate;
                if (combinedBlob.Number < blob.Number)
                    combinedBlob.Number = blob.Number;

                foreach (var entry in blob.Entries)
                {
                    entries.Add(entry);
                }
                combinedBlob.JwtAlg = blob.JwtAlg;
            }

            combinedBlob.Entries = entries.ToArray();
            return combinedBlob;
        }

        protected async Task<string> DownloadStringAsync(string url)
        {
            return await _httpClient.GetStringAsync(url);
        }

        protected async Task<byte[]> DownloadDataAsync(string url)
        {
            return await _httpClient.GetByteArrayAsync(url);
        }

        private X509Certificate2 GetX509Certificate(string key)
        {
            try
            {
                var certBytes = Convert.FromBase64String(key);
                return new X509Certificate2(certBytes);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Could not parse X509 certificate.", ex);
            }
        }

        public async Task<MetadataBLOBPayload> DeserializeAndValidateBlob(string rawBLOBJwt)
        {
            if (string.IsNullOrWhiteSpace(rawBLOBJwt))
                throw new ArgumentNullException(nameof(rawBLOBJwt));

            var jwtParts = rawBLOBJwt.Split('.');

            if (jwtParts.Length != 3)
                throw new ArgumentException("The JWT does not have the 3 expected components");

            var blobHeader = jwtParts.First();
            var tokenHeader = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(blobHeader)));

            var blobAlg = tokenHeader["alg"]?.Value<string>();

            if(blobAlg is null)
                throw new ArgumentNullException("No alg value was present in the BLOB header.");

            var x5cArray = tokenHeader["x5c"] as JArray;

            if (x5cArray is null)
                throw new ArgumentException("No x5c array was present in the BLOB header.");

            var rootCert = GetX509Certificate(ROOT_CERT);
            var blobCertStrings = x5cArray.Values<string>().ToList();
            var blobCertificates = new List<X509Certificate2>();
            var blobPublicKeys = new List<SecurityKey>();

            foreach (var certString in blobCertStrings)
            {
                var cert = GetX509Certificate(certString);
                blobCertificates.Add(cert);

                var ecdsaPublicKey = cert.GetECDsaPublicKey();
                if(ecdsaPublicKey != null)
                    blobPublicKeys.Add(new ECDsaSecurityKey(ecdsaPublicKey));
                
                var rsa = cert.GetRSAPublicKey();
                if(rsa != null)
                    blobPublicKeys.Add(new RsaSecurityKey(rsa));
            }
 
            var certChain = new X509Chain();
            certChain.ChainPolicy.ExtraStore.Add(rootCert);
            certChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = blobPublicKeys,
            };

            var tokenHandler = new JwtSecurityTokenHandler() 
            {
                // 250k isn't enough bytes for conformance test tool
                // https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/1097
                MaximumTokenSizeInBytes = rawBLOBJwt.Length
            };

            tokenHandler.ValidateToken(
                rawBLOBJwt,
                validationParameters,
                out var validatedToken);

            if(blobCertificates.Count > 1)
            {
                certChain.ChainPolicy.ExtraStore.AddRange(blobCertificates.Skip(1).ToArray());
            }
            
            var certChainIsValid = certChain.Build(blobCertificates.First());
            
            // if the root is trusted in the context we are running in, valid should be true here
            if (!certChainIsValid)
            {
                foreach (var element in certChain.ChainElements)
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
                if (rootCert.Thumbprint == certChain.ChainElements[certChain.ChainElements.Count - 1].Certificate.Thumbprint &&
                    // and that the number of elements in the chain accounts for what was in x5c plus the root we added
                    certChain.ChainElements.Count == (blobCertStrings.Count + 1) &&
                    // and that the root cert has exactly one status listed against it
                    certChain.ChainElements[certChain.ChainElements.Count - 1].ChainElementStatus.Length == 1 &&
                    // and that that status is a status of exactly UntrustedRoot
                    certChain.ChainElements[certChain.ChainElements.Count - 1].ChainElementStatus[0].Status == X509ChainStatusFlags.UntrustedRoot)
                {
                    // if we are good so far, that is a good sign
                    certChainIsValid = true;
                    for (var i = 0; i < certChain.ChainElements.Count - 1; i++)
                    {
                        // check each non-root cert to verify zero status listed against it, otherwise, invalidate chain
                        if (0 != certChain.ChainElements[i].ChainElementStatus.Length)
                            certChainIsValid = false;
                    }
                }
            }

            if (!certChainIsValid)
                throw new Fido2VerificationException("Failed to validate cert chain while parsing BLOB");

            var blobPayload = ((JwtSecurityToken)validatedToken).Payload.SerializeToJson();

            var blob = Newtonsoft.Json.JsonConvert.DeserializeObject<MetadataBLOBPayload>(blobPayload);
            blob.JwtAlg = blobAlg;
            return blob;
        }
    }
}
