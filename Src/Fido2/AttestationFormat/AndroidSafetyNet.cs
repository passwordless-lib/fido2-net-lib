using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

using Fido2NetLib.Objects;
using Microsoft.IdentityModel.Tokens;
using PeterO.Cbor;

namespace Fido2NetLib
{
    internal sealed class AndroidSafetyNet : AttestationVerifier
    {
        private readonly int _driftTolerance;

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
            if (attStmt["ver"].Type != CBORType.TextString ||
                attStmt["ver"].AsString().Length is 0)
            {
                throw new Fido2VerificationException("Invalid version in SafetyNet data");
            }

            // 2. Verify that response is a valid SafetyNet response of version ver
            var ver = attStmt["ver"].AsString();

            if (attStmt["response"].Type != CBORType.ByteString ||
                attStmt["response"].GetByteString().Length is 0)
                throw new Fido2VerificationException("Invalid response in SafetyNet data");

            var response = attStmt["response"].GetByteString();
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
            var keys = new List<SecurityKey>();

            for (int i = 0; i < certs.Length; i++)
            {
                var certString = x5cStrings[i];
                var cert = GetX509Certificate(certString);
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

            var nonce = "";
            bool? ctsProfileMatch = null;
            var timestampMs = DateTimeHelper.UnixEpoch;

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
                    timestampMs = DateTimeHelper.UnixEpoch.AddMilliseconds(double.Parse(claim.Value));
                }
            }

            var notAfter = DateTime.UtcNow.AddMilliseconds(_driftTolerance);
            var notBefore = DateTime.UtcNow.AddMinutes(-1).AddMilliseconds(-(_driftTolerance));
            if ((notAfter < timestampMs) || ((notBefore) > timestampMs))
            {
                throw new Fido2VerificationException(string.Format("SafetyNet timestampMs must be present and between one minute ago and now, got: {0}", timestampMs.ToString()));
            }

            // 3. Verify that the nonce in the response is identical to the SHA-256 hash of the concatenation of authenticatorData and clientDataHash
            if (nonce is "")
                throw new Fido2VerificationException("Nonce value not found in SafetyNet attestation");

            byte[] nonceHash;
            try
            {
                nonceHash = Convert.FromBase64String(nonce);
            }
            catch (Exception ex)
            {
                throw new Fido2VerificationException("Nonce value not base64string in SafetyNet attestation", ex);
            }
            
            var dataHash = CryptoUtils.Sha256HashData(Data);

            if (!dataHash.AsSpan().SequenceEqual(nonceHash))
                throw new Fido2VerificationException(
                    string.Format(
                        "SafetyNet response nonce / hash value mismatch, nonce {0}, hash {1}", 
                        BitConverter.ToString(nonceHash).Replace("-", ""), 
                        BitConverter.ToString(dataHash).Replace("-", "")
                        )
                    );
            

            // 4. Let attestationCert be the attestation certificate
            var attestationCert = certs[0];
            var subject = attestationCert.GetNameInfo(X509NameType.DnsName, false);

            // 5. Verify that the attestation certificate is issued to the hostname "attest.android.com"
            if (subject is not "attest.android.com")
                throw new Fido2VerificationException(string.Format("SafetyNet attestation cert DnsName invalid, want {0}, got {1}", "attest.android.com", subject));

            // 6. Verify that the ctsProfileMatch attribute in the payload of response is true
            if (ctsProfileMatch is null)
                throw new Fido2VerificationException("SafetyNet response ctsProfileMatch missing");
                        
            if (true != ctsProfileMatch)
                throw new Fido2VerificationException("SafetyNet response ctsProfileMatch false");

            return (AttestationType.Basic, new X509Certificate2[] { attestationCert });
        }
    }
}
