using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    internal sealed class AppleAppAttest : AttestationVerifier
    {
        public static byte[] GetAppleAppIdFromCredCertExtValue(X509ExtensionCollection exts)
        {
            var appleExtension = exts.Cast<X509Extension>().FirstOrDefault(e => e.Oid!.Value is "1.2.840.113635.100.8.5");

            if (appleExtension is null || appleExtension.RawData is null)
                throw new Fido2VerificationException("Extension with OID 1.2.840.113635.100.8.5 not found on Apple AppAttest credCert");

                var appleAttestationASN = Asn1Element.Decode(appleExtension.RawData);
                appleAttestationASN.CheckTag(Asn1Tag.Sequence);
                foreach (Asn1Element s in appleAttestationASN.Sequence)
                {
                    switch (s.TagValue)
                    {
                        case 1204:
                            // App ID is the concatenation of your 10-digit team identifier, a period, and your app's CFBundleIdentifier value 
                            s.CheckExactSequenceLength(1);
                            s[0].CheckTag(Asn1Tag.PrimitiveOctetString);
                            return s[0].GetOctetString();
                        default:
                            break;
                    }
                }
            throw new Fido2VerificationException("Apple AppAttest attestation extension 1.2.840.113635.100.8.5 has invalid data");
        }

        // From https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
        internal static readonly string appleAppAttestationRootCA = "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD";
        
        public static readonly X509Certificate2 AppleAppAttestRootCA = new(Convert.FromBase64String(appleAppAttestationRootCA));

        // From https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
        // "aaguid field is either appattestdevelop if operating in the development environment..."
        // 61707061-7474-6573-7464-6576656c6f70
        public static readonly Guid devAaguid = new("61707061-7474-6573-7464-6576656c6f70");

        // "...or appattest followed by seven 0x00 bytes if operating in the production environment"
        // 61707061-7474-6573-7400-000000000000
        public static readonly Guid prodAaguid = new("61707061-7474-6573-7400-000000000000");

        public override (AttestationType, X509Certificate2[]) Verify()
        {
            // 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest, starting from the credential certificate in the first data buffer in the array (credcert).
            if (!(X5c is CborArray { Length: 2 } x5cArray && x5cArray[0] is CborByteString { Length: > 0 } && x5cArray[1] is CborByteString { Length: > 0 }))
            {
                throw new Fido2VerificationException("Malformed x5c in Apple AppAttest attestation");
            }

            // Verify the validity of the certificates using Apple's App Attest root certificate.
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.CustomTrustStore.Add(AppleAppAttestRootCA);
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

            X509Certificate2 intermediateCert = new((byte[])x5cArray[1]);
            chain.ChainPolicy.ExtraStore.Add(intermediateCert);

            X509Certificate2 credCert = new((byte[])x5cArray[0]);
            if (AuthData.AttestedCredentialData.AaGuid.Equals(devAaguid))
            {
                // Allow expired leaf cert in development environment
                chain.ChainPolicy.VerificationTime = credCert.NotBefore.AddSeconds(1);
            }

            if (!chain.Build(credCert))
            {
                throw new Fido2VerificationException("Failed to build chain in Apple AppAttest attestation");
            }

            // 2. Create clientDataHash as the SHA256 hash of the one-time challenge your server sends to your app before performing the attestation, and append that hash to the end of the authenticator data (authData from the decoded object).
            // 3. Generate a new SHA256 hash of the composite item to create nonce.
            // 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER - encoded ASN.1 sequence.Decode the sequence and extract the single octet string that it contains. Verify that the string equals nonce.
            // Steps 2 - 4 done in the "apple" format verifier
            Apple apple = new();
            (var attType, var trustPath) = apple.Verify(attStmt, authenticatorData, clientDataHash);

            // 5. Create the SHA256 hash of the public key in credCert, and verify that it matches the key identifier from your app.
            var keyIdentifer = SHA256.HashData(credCert.GetPublicKey());
            if (!Convert.FromHexString(credCert.GetNameInfo(X509NameType.SimpleName, false)).SequenceEqual(keyIdentifer))
            {
                throw new Fido2VerificationException("Public key hash does not match key identifier in Apple AppAttest attestation");
            }
            
            // 6. Compute the SHA256 hash of your app's App ID, and verify that it’s the same as the authenticator data's RP ID hash.
            var appId = GetAppleAppIdFromCredCertExtValue(credCert.Extensions);
            if (!SHA256.HashData(appId).SequenceEqual(AuthData.RpIdHash))
            {
                throw new Fido2VerificationException("App ID hash does not match RP ID hash in Apple AppAttest attestation");
            }

            // 7. Verify that the authenticator data's counter field equals 0.
            if (AuthData.SignCount != 0)
            {
                throw new Fido2VerificationException("Sign count does not equal 0 in Apple AppAttest attestation");
            }

            // 8. Verify that the authenticator data's aaguid field is either appattestdevelop if operating in the development environment, or appattest followed by seven 0x00 bytes if operating in the production environment.
            if (!AuthData.AttestedCredentialData.AaGuid.Equals(devAaguid) && !AuthData.AttestedCredentialData.AaGuid.Equals(prodAaguid))
            {
                throw new Fido2VerificationException("Invalid aaguid encountered in Apple AppAttest attestation");
            }

            // 9. Verify that the authenticator data's credentialId field is the same as the key identifier.
            if (!AuthData.AttestedCredentialData.CredentialID.SequenceEqual(keyIdentifer))
            {
                throw new Fido2VerificationException("Mismatch between credentialId and keyIdentifier in Apple AppAttest attestation");
            }

            return (attType, trustPath);
        }
    }
}
