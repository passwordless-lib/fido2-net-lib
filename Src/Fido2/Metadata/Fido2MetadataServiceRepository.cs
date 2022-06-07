using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Serialization;

using Microsoft.IdentityModel.Tokens;

namespace Fido2NetLib
{
    public sealed class Fido2MetadataServiceRepository : IMetadataRepository
    {
        private const string ROOT_CERT =
        "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G" +
        "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp" +
        "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4" +
        "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG" +
        "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI" +
        "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8" +
        "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT" +
        "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm" +
        "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd" +
        "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ" +
        "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw" +
        "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o" +
        "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU" +
        "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp" +
        "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK" +
        "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX" +
        "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs" +
        "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH" +
        "WD9f";

        private readonly string _blobUrl = "https://mds.fidoalliance.org/";
        private readonly IHttpClientFactory _httpClientFactory;

        public Fido2MetadataServiceRepository(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<MetadataStatement?>(entry.MetadataStatement);
        }

        public async Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            var rawBLOB = await GetRawBlobAsync(cancellationToken);
            return await DeserializeAndValidateBlobAsync(rawBLOB, cancellationToken);
        }

        private async Task<string> GetRawBlobAsync(CancellationToken cancellationToken)
        {
            var url = _blobUrl;
            return await DownloadStringAsync(url, cancellationToken);
        }

        private async Task<string> DownloadStringAsync(string url, CancellationToken cancellationToken)
        {
            return await _httpClientFactory
                .CreateClient(nameof(Fido2MetadataServiceRepository))
                .GetStringAsync(url, cancellationToken);
        }

        private async Task<byte[]> DownloadDataAsync(string url, CancellationToken cancellationToken)
        {
            return await _httpClientFactory
                .CreateClient(nameof(Fido2MetadataServiceRepository))
                .GetByteArrayAsync(url, cancellationToken);
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

        private async Task<MetadataBLOBPayload> DeserializeAndValidateBlobAsync(string rawBLOBJwt, CancellationToken cancellationToken)
        {
           
            if (string.IsNullOrWhiteSpace(rawBLOBJwt))
                throw new ArgumentNullException(nameof(rawBLOBJwt));

            var jwtParts = rawBLOBJwt.Split('.');

            if (jwtParts.Length != 3)
                throw new ArgumentException("The JWT does not have the 3 expected components");

            var blobHeaderString = jwtParts[0];
            using var blobHeaderDoc = JsonDocument.Parse(Base64Url.Decode(blobHeaderString));
            var blobHeader = blobHeaderDoc.RootElement;

            string blobAlg = blobHeader.TryGetProperty("alg", out var algEl)
                ? algEl.GetString()!
                : throw new ArgumentNullException("No alg value was present in the BLOB header.");

            string[] keyStrings = blobHeader.TryGetProperty("x5c", out var x5cEl) && x5cEl.ValueKind is JsonValueKind.Array
                ? x5cEl.ToStringArray()
                : throw new ArgumentNullException("No x5c array was present in the BLOB header.");

            if (keyStrings.Length is 0)
                throw new ArgumentException("No keys were present in the BLOB header.");

            var rootCert = GetX509Certificate(ROOT_CERT);
            var blobCerts = new X509Certificate2[keyStrings.Length];
            var keys = new SecurityKey[keyStrings.Length];

            for (int i = 0; i < blobCerts.Length; i++)
            {
                var cert = GetX509Certificate(keyStrings[i]);

                blobCerts[i] = cert;

                if (cert.GetECDsaPublicKey() is ECDsa ecdsaPublicKey)
                {
                    keys[i] = new ECDsaSecurityKey(ecdsaPublicKey);
                }
                else if (cert.GetRSAPublicKey() is RSA rsaPublicKey)
                {
                    keys[i] = new RsaSecurityKey(rsaPublicKey);
                }
                else
                {
                    throw new Fido2MetadataException("Unknown certificate algorithm");
                }
            }
            var blobPublicKeys = keys.ToArray(); // defensive copy

            var certChain = new X509Chain();
            certChain.ChainPolicy.ExtraStore.Add(rootCert);
            certChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = blobPublicKeys
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

            if(blobCerts.Length > 1)
            {
                certChain.ChainPolicy.ExtraStore.AddRange(blobCerts.Skip(1).ToArray());
            }
            
            var certChainIsValid = certChain.Build(blobCerts[0]);
            // if the root is trusted in the context we are running in, valid should be true here
            if (!certChainIsValid)
            {
                foreach (var element in certChain.ChainElements)
                {
                    if (element.Certificate.Issuer != element.Certificate.Subject)
                    {
                        var cdp = CryptoUtils.CDPFromCertificateExts(element.Certificate.Extensions);
                        var crlFile = await DownloadDataAsync(cdp, cancellationToken);
                        if (CryptoUtils.IsCertInCRL(crlFile, element.Certificate))
                            throw new Fido2VerificationException($"Cert {element.Certificate.Subject} found in CRL {cdp}");
                    }
                }

                // otherwise we have to manually validate that the root in the chain we are testing is the root we downloaded
                if (rootCert.Thumbprint == certChain.ChainElements[^1].Certificate.Thumbprint &&
                    // and that the number of elements in the chain accounts for what was in x5c plus the root we added
                    certChain.ChainElements.Count == (keyStrings.Length + 1) &&
                    // and that the root cert has exactly one status listed against it
                    certChain.ChainElements[^1].ChainElementStatus.Length == 1 &&
                    // and that that status is a status of exactly UntrustedRoot
                    certChain.ChainElements[^1].ChainElementStatus[0].Status == X509ChainStatusFlags.UntrustedRoot)
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

            var blob =  JsonSerializer.Deserialize(blobPayload, FidoModelSerializer.Default.MetadataBLOBPayload)!;
            blob.JwtAlg = blobAlg;
            return blob;
        }
    }
}
