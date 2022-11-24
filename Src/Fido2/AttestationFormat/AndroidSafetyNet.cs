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

    private static X509Certificate2 GetX509Certificate(string certString)
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

    public override (AttestationType, X509Certificate2[]) Verify()
    {
        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform 
        // CBOR decoding on it to extract the contained fields
        // (handled in base class)
        if (!(attStmt["ver"] is CborTextString { Length: > 0 }))
        {
            throw new Fido2VerificationException("Invalid version in SafetyNet data");
        }

        // 2. Verify that response is a valid SafetyNet response of version ver
        var ver = (string)attStmt["ver"]!;

        if (!(attStmt["response"] is CborByteString { Length: > 0}))
            throw new Fido2VerificationException("Invalid response in SafetyNet data");

        var response = (byte[])attStmt["response"]!;
        var responseJWT = Encoding.UTF8.GetString(response);

        if (string.IsNullOrWhiteSpace(responseJWT))
            throw new Fido2VerificationException("SafetyNet response null or whitespace");

        var jwtParts = responseJWT.Split('.');

        if (jwtParts.Length != 3)
            throw new Fido2VerificationException("SafetyNet response JWT does not have the 3 expected components");

        string jwtHeaderString = jwtParts[0];

        using var jwtHeaderJsonDoc = JsonDocument.Parse(Base64Url.Decode(jwtHeaderString));
        var jwtHeaderJson = jwtHeaderJsonDoc.RootElement;

        string[] x5cStrings = jwtHeaderJson.TryGetProperty("x5c", out var x5cEl) && x5cEl.ValueKind is JsonValueKind.Array
            ? x5cEl.ToStringArray()
            : throw new Fido2VerificationException("SafetyNet response JWT header missing x5c");

        if (x5cStrings.Length is 0)
            throw new Fido2VerificationException("No keys were present in the TOC header in SafetyNet response JWT");

        var certs = new X509Certificate2[x5cStrings.Length];
        var keys = new List<SecurityKey>(certs.Length);

        for (int i = 0; i < certs.Length; i++)
        {
            var cert = GetX509Certificate(x5cStrings[i]);
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
            tokenHandler.ValidateToken(responseJWT, validationParameters, out validatedToken);
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
        SHA256.HashData(Data, dataHash);

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
