﻿using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
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

        public Fido2MetadataServiceRepository(string accessToken, HttpClient httpClient)
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
            var statementBase64Url = await DownloadStringAsync(entry.Url + "/?token=" + WebUtility.UrlEncode(_token));
            var tocAlg = await GetTocAlg();

            var statementBytes = Base64Url.Decode(statementBase64Url);
            var statementString = Encoding.UTF8.GetString(statementBytes, 0, statementBytes.Length);
            var statement = Newtonsoft.Json.JsonConvert.DeserializeObject<MetadataStatement>(statementString);
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
            var url = _tocUrl + "/?token=" + WebUtility.UrlEncode(_token);
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

        private ECDsaSecurityKey GetECDsaPublicKey(string certString)
        {
            try
            {
                var certBytes = Convert.FromBase64String(certString);
                var cert = new X509Certificate2(certBytes);
                var publicKey = cert.GetECDsaPublicKey();
                return new ECDsaSecurityKey(publicKey);
            }
            catch(Exception ex)
            {
                throw new ArgumentException("Could not parse X509 certificate.", ex);
            }  
        }

        private X509Certificate2 GetX509Certificate(string certString)
        {
            try
            {
                var certBytes = Convert.FromBase64String(certString);
                return new X509Certificate2(certBytes);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Could not parse X509 certificate.", ex);
            }
        }

        protected async Task<MetadataTOCPayload> DeserializeAndValidateToc(string toc)
        {
           
            if (string.IsNullOrWhiteSpace(toc))
                throw new ArgumentNullException(nameof(toc));

            var jwtParts = toc.Split('.');

            if (jwtParts.Length != 3)
                throw new ArgumentException("The JWT does not have the 3 expected components");

            var tocHeaderString = jwtParts.First();
            var tocHeader = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(tocHeaderString)));

            _tocAlg = tocHeader["alg"]?.Value<string>();

            if (_tocAlg == null)
                throw new ArgumentNullException("No alg value was present in the TOC header.");

            var x5cArray = tocHeader["x5c"] as JArray;

            if (x5cArray == null)
                throw new Exception("No x5c array was present in the TOC header.");

            var keyStrings = x5cArray.Values<string>().ToList();

            if (keyStrings.Count == 0)
                throw new ArgumentException("No keys were present in the TOC header.");

            var rootCert = GetX509Certificate(ROOT_CERT);
            var tocCerts = keyStrings.Select(o => GetX509Certificate(o)).ToArray();
            var tocPublicKeys = keyStrings.Select(o => GetECDsaPublicKey(o)).ToArray();

            var certChain = new X509Chain();
            certChain.ChainPolicy.ExtraStore.Add(rootCert);
            certChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = tocPublicKeys,
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            tokenHandler.ValidateToken(
                toc,
                validationParameters,
                out var validatedToken);

            if(tocCerts.Length > 1)
            {
                certChain.ChainPolicy.ExtraStore.AddRange(tocCerts.Skip(1).ToArray());
            }
            
            var certChainIsValid = certChain.Build(tocCerts.First());
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
                    certChain.ChainElements.Count == (keyStrings.Count + 1) &&
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
                throw new Fido2VerificationException("Failed to validate cert chain while parsing TOC");

            var tocPayload = ((JwtSecurityToken)validatedToken).Payload.SerializeToJson();
            return Newtonsoft.Json.JsonConvert.DeserializeObject<MetadataTOCPayload>(tocPayload);
        }
    }
}
