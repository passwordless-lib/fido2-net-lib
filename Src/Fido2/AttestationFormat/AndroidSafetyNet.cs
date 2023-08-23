using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.IdentityModel.Tokens;

namespace Fido2NetLib;

internal sealed class AndroidSafetyNet : AttestationVerifier
{
    private const int _driftTolerance = 0;

    public override (AttestationType, X509Certificate2[]) Verify(VerifyAttestationRequest request)
    {
        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform 
        // CBOR decoding on it to extract the contained fields
        // (handled in base class)

        // 2. Verify that response is a valid SafetyNet response of version ver
        if (!request.TryGetVer(out string? ver))
        {
            throw new Fido2VerificationException(Fido2ErrorMessages.InvalidSafetyNetVersion);
        }

        if (!(request.AttStmt["response"] is CborByteString { Length: > 0 } responseByteString))
            throw new Fido2VerificationException(Fido2ErrorMessages.InvalidSafetyNetResponse);

        var responseJwt = Encoding.UTF8.GetString(responseByteString);

        var jwtComponents = responseJwt.Split('.');

        if (jwtComponents.Length != 3)
            throw new Fido2VerificationException(Fido2ErrorMessages.MalformedSafetyNetJwt);

        byte[] jwtHeaderBytes;

        try
        {
            jwtHeaderBytes = Base64Url.Decode(jwtComponents[0]);
        }
        catch (FormatException)
        {
            throw new Fido2VerificationException(Fido2ErrorMessages.MalformedSafetyNetJwt);
        }

        using var jwtHeaderJsonDoc = JsonDocument.Parse(jwtHeaderBytes);
        var jwtHeaderJson = jwtHeaderJsonDoc.RootElement;

        if (!jwtHeaderJson.TryGetProperty("x5c", out var x5cEl))
        {
            throw new Fido2VerificationException("SafetyNet response JWT header missing x5c");
        }

        if (!x5cEl.TryDecodeArrayOfBase64EncodedBytes(out var x5cRawKeys))
        {        
            throw new Fido2VerificationException("SafetyNet response JWT header has a malformed x5c value");
        }

        if (x5cRawKeys.Length is 0)
        {
            throw new Fido2VerificationException("No keys were present in the TOC header in SafetyNet response JWT");
        }

        var certs = new X509Certificate2[x5cRawKeys.Length];
        var keys = new List<SecurityKey>(certs.Length);

        for (int i = 0; i < certs.Length; i++)
        {
            var cert = X509CertificateHelper.CreateFromRawData(x5cRawKeys[i]);
            certs[i] = cert;

            if (cert.GetECDsaPublicKey() is ECDsa ecdsaPublicKey)
            {
                keys.Add(new ECDsaSecurityKey(ecdsaPublicKey));
            }
            else if (cert.GetRSAPublicKey() is RSA rsaPublicKey)
            {
                keys.Add(new RsaSecurityKey(rsaPublicKey));
            }
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = keys
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        SecurityToken validatedToken;
        try
        { 
            tokenHandler.ValidateToken(responseJwt, validationParameters, out validatedToken);
        }
        catch (SecurityTokenException ex)
        {
            throw new Fido2VerificationException("SafetyNet response security token validation failed", ex);
        }

        string? nonce = null;
        bool? ctsProfileMatch = null;
        DateTimeOffset? timestamp = null;

        var jwtToken = (JwtSecurityToken)validatedToken;

        foreach (var claim in jwtToken.Claims)
        {
            if (claim is { Type: "nonce", ValueType: "http://www.w3.org/2001/XMLSchema#string" } && claim.Value.Length != 0)
            {
                nonce = claim.Value;
            }
            if (claim is { Type: "ctsProfileMatch", ValueType: "http://www.w3.org/2001/XMLSchema#boolean" })
            {
                ctsProfileMatch = bool.Parse(claim.Value);
            }
            if (claim is { Type: "timestampMs", ValueType: "http://www.w3.org/2001/XMLSchema#integer64" })
            {
                timestamp = DateTimeOffset.UnixEpoch.AddMilliseconds(double.Parse(claim.Value, CultureInfo.InvariantCulture));
            }
        }

        if (!timestamp.HasValue)
        {
            throw new Fido2VerificationException($"SafetyNet timestampMs not found SafetyNet attestation");
        }

        var notAfter = DateTimeOffset.UtcNow.AddMilliseconds(_driftTolerance);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-1).AddMilliseconds(-(_driftTolerance));
        if ((notAfter < timestamp) || ((notBefore) > timestamp.Value))
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"SafetyNet timestampMs must be between one minute ago and now, got: {timestamp:o}");
        }

        // 3. Verify that the nonce in the response is identical to the SHA-256 hash of the concatenation of authenticatorData and clientDataHash
        if (string.IsNullOrEmpty(nonce))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Nonce value not found in SafetyNet attestation");

        byte[] nonceHash;
        try
        {
            nonceHash = Convert.FromBase64String(nonce);
        }
        catch (Exception ex)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Nonce value not base64string in SafetyNet attestation", ex);
        }

        Span<byte> dataHash = stackalloc byte[32];
        SHA256.HashData(request.Data, dataHash);

        if (!dataHash.SequenceEqual(nonceHash))
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"SafetyNet response nonce / hash value mismatch, nonce {Convert.ToHexString(nonceHash)}, hash {Convert.ToHexString(dataHash)}");
        }

        // 4. Let attestationCert be the attestation certificate
        var attestationCert = certs[0];
        var subject = attestationCert.GetNameInfo(X509NameType.DnsName, false);

        // 5. Verify that the attestation certificate is issued to the hostname "attest.android.com"
        if (subject is not "attest.android.com")
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"Invalid SafetyNet attestation cert DnsName. Expected 'attest.android.com'. Was '{subject}'");

        // 6. Verify that the ctsProfileMatch attribute in the payload of response is true
        if (ctsProfileMatch is null)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "SafetyNet response ctsProfileMatch missing");
                    
        if (true != ctsProfileMatch)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "SafetyNet response ctsProfileMatch false");

        return (AttestationType.Basic, new X509Certificate2[] { attestationCert });
    }
}
