using System;
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
    public class Fido2MetadataServiceRepository : IMetadataRepository
    {
        //var rootFile = client.DownloadData("https://mds.fidoalliance.org/Root.cer");
        protected const string ROOT_CERT = 
            "MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkG" +
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

        protected readonly string _token;
        protected readonly string _tocUrl;
        protected readonly HttpClient _httpClient;

        protected string _tocAlg;

        public Fido2MetadataServiceRepository(string accessToken, HttpClient httpClient) //Fido2Configuration options
        {
            _tocUrl = "https://mds2.fidoalliance.org";
            _token = accessToken;
            _httpClient = httpClient ?? new HttpClient();
        }

        private Task<string> GetTocAlg()
        {
            if (!string.IsNullOrEmpty(_tocAlg))
            {
                return Task.FromResult(_tocAlg);
            }
            else
            {
                throw new InvalidOperationException("Could not determine the TOC algorithm");
            }
        }

        public async Task<MetadataStatement> GetMetadataStatement(MetadataTOCPayloadEntry entry)
        {
            var statementBase64Url = await DownloadStringAsync(entry.Url + "/?token=" + _token);
            var tocAlg = await GetTocAlg();

            var statementBytes = Base64Url.Decode(statementBase64Url);
            var statementString = Encoding.UTF8.GetString(statementBytes, 0, statementBytes.Length);
            var statement = JsonConvert.DeserializeObject<MetadataStatement>(statementString);
            using(HashAlgorithm hasher = CryptoUtils.GetHasher(new HashAlgorithmName(tocAlg)))
            {
                statement.Hash = Base64Url.Encode(hasher.ComputeHash(Encoding.UTF8.GetBytes(statementBase64Url)));
            }

            if(!HashesAreEqual(entry.Hash, statement.Hash))
                throw new Fido2VerificationException("TOC entry and statement hashes do not match");

            return statement;
        }

        private bool HashesAreEqual(string a, string b)
        {
            var hashA = Base64Url.Decode(a);
            var hashB = Base64Url.Decode(b);

            return hashA.SequenceEqual(hashB);
        }

        public async Task<MetadataTOCPayload> GetToc()
        {
            var rawToc = await GetRawToc();
            return await DeserializeAndValidateToc(rawToc);
        }

        protected async Task<string> GetRawToc()
        {
            var url = _tocUrl + "/?token=" + _token;
            return await DownloadStringAsync(url);
        }

        protected async Task<string> DownloadStringAsync(string url)
        {
            return await _httpClient.GetStringAsync(url);
        }

        protected async Task<byte[]> DownloadDataAsync(string url)
        {
            return await _httpClient.GetByteArrayAsync(url);
        }

        protected async Task<MetadataTOCPayload> DeserializeAndValidateToc(string toc)
        {
            var jwtToken = new JwtSecurityToken(toc);
            _tocAlg = jwtToken.Header["alg"] as string;
            var keys = (jwtToken.Header["x5c"] as JArray)
                .Values<string>()
                .Select(x => new ECDsaSecurityKey(
                    (ECDsa)(new X509Certificate2(Convert.FromBase64String(x)).GetECDsaPublicKey())))
                .ToArray();

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
            if (false == valid)
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
            if (false == valid)
                throw new Fido2VerificationException("Failed to validate cert chain while parsing TOC");
            return JsonConvert.DeserializeObject<MetadataTOCPayload>(payload);
        }
    }
}
