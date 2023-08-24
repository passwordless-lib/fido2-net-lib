﻿using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Internal;
using Fido2NetLib.Serialization;

using Microsoft.IdentityModel.Tokens;

namespace Fido2NetLib;

public sealed class ConformanceMetadataRepository : IMetadataRepository
{
    private static ReadOnlySpan<byte> ROOT_CERT =>
        "MIICaDCCAe6gAwIBAgIPBCqih0DiJLW7+UHXx/o1MAoGCCqGSM49BAMDMGcxCzAJ"u8 +
        "BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF"u8 +
        "IE1ldGFkYXRhIDMgQkxPQiBST09UIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG"u8 +
        "QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC"u8 +
        "VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh"u8 +
        "dGEgMyBCTE9CIFJPT1QgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ"u8 +
        "BgcqhkjOPQIBBgUrgQQAIgNiAASKYiz3YltC6+lmxhPKwA1WFZlIqnX8yL5RybSL"u8 +
        "TKFAPEQeTD9O6mOz+tg8wcSdnVxHzwnXiQKJwhrav70rKc2ierQi/4QUrdsPes8T"u8 +
        "EirZOkCVJurpDFbXZOgs++pa4XmjYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E"u8 +
        "BTADAQH/MB0GA1UdDgQWBBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAfBgNVHSMEGDAW"u8 +
        "gBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAKBggqhkjOPQQDAwNoADBlAjEA/xFsgri0"u8 +
        "xubSa3y3v5ormpPqCwfqn9s0MLBAtzCIgxQ/zkzPKctkiwoPtDzI51KnAjAmeMyg"u8 +
        "X2S5Ht8+e+EQnezLJBJXtnkRWY+Zt491wgt/AwSs5PHHMv5QgjELOuMxQBc="u8;

    private readonly HttpClient _httpClient;

    private readonly string _origin;

    private readonly string _getEndpointsUrl = "https://mds3.fido.tools/getEndpoints";

    public ConformanceMetadataRepository(HttpClient? client, string origin)
    {
        _httpClient = client ?? new HttpClient();
        _origin = origin;
    }

    public Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
    {
        return Task.FromResult<MetadataStatement?>(entry.MetadataStatement);
    }

    public async Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
    {
        var req = new GetBLOBRequest(_origin);

        var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(req, FidoSerializerContext.Default.GetBLOBRequest))
        {
            Headers = { { "Content-Type", "application/json" } }
        };

        using var response = await _httpClient.PostAsync(_getEndpointsUrl, content, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new Exception($"{_getEndpointsUrl} returned {response.StatusCode} error");
        }

        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        MDSGetEndpointResponse? result = await JsonSerializer.DeserializeAsync(responseStream, FidoSerializerContext.Default.MDSGetEndpointResponse, cancellationToken);
        var conformanceEndpoints = result!.Result;

        var combinedBlob = new MetadataBLOBPayload
        {
            Number = -1,
            NextUpdate = "2099-08-07"
        };

        var entries = new List<MetadataBLOBPayloadEntry>();

        foreach (var blobUrl in conformanceEndpoints)
        {
            var rawBlob = await DownloadStringAsync(blobUrl, cancellationToken);

            MetadataBLOBPayload blob;

            try
            {
                blob = await DeserializeAndValidateBlobAsync(rawBlob, cancellationToken);
            }
            catch
            {
                continue;
            }

            if (string.Compare(blob.NextUpdate, combinedBlob.NextUpdate, StringComparison.InvariantCulture) < 0)
                combinedBlob.NextUpdate = blob.NextUpdate;

            if (combinedBlob.Number < blob.Number)
                combinedBlob.Number = blob.Number;

            entries.AddRange(blob.Entries);

            combinedBlob.JwtAlg = blob.JwtAlg;
        }

        combinedBlob.Entries = entries.ToArray();
        return combinedBlob;
    }

    private Task<string> DownloadStringAsync(string url, CancellationToken cancellationToken)
    {
        return _httpClient.GetStringAsync(url, cancellationToken);
    }

    private Task<byte[]> DownloadDataAsync(string url, CancellationToken cancellationToken)
    {
        return _httpClient.GetByteArrayAsync(url, cancellationToken);
    }

    public async Task<MetadataBLOBPayload> DeserializeAndValidateBlobAsync(string rawBLOBJwt, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rawBLOBJwt))
            throw new ArgumentNullException(nameof(rawBLOBJwt));

        var jwtParts = rawBLOBJwt.Split('.');

        if (jwtParts.Length != 3)
            throw new Fido2MetadataException("The JWT does not have the 3 expected components");

        var blobHeader = jwtParts[0];
        using var jsonDoc = JsonDocument.Parse(Base64Url.Decode(blobHeader));
        var tokenHeader = jsonDoc.RootElement;

        var blobAlg = tokenHeader.TryGetProperty("alg", out var algEl)
            ? algEl.GetString()!
            : throw new Fido2MetadataException("No alg value was present in the BLOB header.");

        if (!tokenHeader.TryGetProperty("x5c", out var x5cEl))
        {
            throw new Fido2MetadataException("No x5c array was present in the BLOB header.");
        }

        if (!x5cEl.TryDecodeArrayOfBase64EncodedBytes(out var x5cRawKeys))
        {
            throw new Fido2MetadataException("Malformed x5c array in the BLOB header.");
        }

        var rootCert = X509CertificateHelper.CreateFromBase64String(ROOT_CERT);
        var blobCertificates = new X509Certificate2[x5cRawKeys.Length];
        var blobPublicKeys = new List<SecurityKey>(x5cRawKeys.Length);

        for (int i = 0; i < x5cRawKeys.Length; i++)
        {
            var cert = X509CertificateHelper.CreateFromRawData(x5cRawKeys[i]);
            blobCertificates[i] = cert;

            if (cert.GetECDsaPublicKey() is ECDsa ecdsaPublicKey)
                blobPublicKeys.Add(new ECDsaSecurityKey(ecdsaPublicKey));

            else if (cert.GetRSAPublicKey() is RSA rsa)
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

        if (blobCertificates.Length > 1)
        {
            certChain.ChainPolicy.ExtraStore.AddRange(blobCertificates.Skip(1).ToArray());
        }

        var certChainIsValid = certChain.Build(blobCertificates[0]);

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
            if (rootCert.Thumbprint.Equals(certChain.ChainElements[^1].Certificate.Thumbprint, StringComparison.Ordinal) &&
                // and that the number of elements in the chain accounts for what was in x5c plus the root we added
                certChain.ChainElements.Count == (x5cRawKeys.Length + 1) &&
                // and that the root cert has exactly one status with the value of UntrustedRoot
                certChain.ChainElements[^1].ChainElementStatus is [{ Status: X509ChainStatusFlags.UntrustedRoot }])
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

        MetadataBLOBPayload blob = JsonSerializer.Deserialize(blobPayload, FidoModelSerializerContext.Default.MetadataBLOBPayload)!;
        blob.JwtAlg = blobAlg;
        return blob;
    }
}
