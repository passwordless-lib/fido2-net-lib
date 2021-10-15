using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib
{
    internal sealed class AndroidKey : AttestationVerifier
    {
        public static byte[]? AttestationExtensionBytes(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid!.Value is "1.3.6.1.4.1.11129.2.1.17") // AttestationRecordOid
                {
                    return ext.RawData;
                }
            }
            return null;
        }

        public static byte[] GetAttestationChallenge(byte[] attExtBytes)
        {
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // attestationChallenge at index 4

            var keyDescription = Asn1Element.Decode(attExtBytes);
            return keyDescription[4].GetOctetString();
        }

        public static bool FindAllApplicationsField(byte[] attExtBytes)
        {
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // check both software and tee enforced AuthorizationList objects for presense of "allApplications" tag, number 600

            var keyDescription = Asn1Element.Decode(attExtBytes);

            var softwareEnforced = keyDescription[6].Sequence;
            foreach (Asn1Element s in softwareEnforced)
            {
                switch (s.TagValue)
                {
                    case 600:
                        return true;
                    default:
                        break;
                }
            }

            var teeEnforced = keyDescription[7].Sequence;
            foreach (Asn1Element s in teeEnforced)
            {
                switch (s.TagValue)
                {
                    case 600:
                        return true;
                    default:
                        break;
                }
            }

            return false;
        }

        public static bool IsOriginGenerated(byte[] attExtBytes)
        {
            int softwareEnforcedOriginValue = 0;
            int teeEnforcedOriginValue = 0;
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // origin tag is 702
            var keyDescription = Asn1Element.Decode(attExtBytes);

            var softwareEnforced = keyDescription[6].Sequence;
            foreach (Asn1Element s in softwareEnforced)
            {
                switch (s.TagValue)
                {
                    case 702:
                        softwareEnforcedOriginValue = s[0].GetInt32();
                        break;
                    default:
                        break;
                }
            }
            
            var teeEnforced = keyDescription[7].Sequence;
            foreach (Asn1Element s in teeEnforced)
            {
                switch (s.TagValue)
                {
                    case 702:
                        teeEnforcedOriginValue = s[0].GetInt32();
                        break;
                    default:
                        break;
                }
            }
            
            return (softwareEnforcedOriginValue is 0 && teeEnforcedOriginValue is 0);
        }

        public static bool IsPurposeSign(byte[] attExtBytes)
        {
            int softwareEnforcedPurposeValue = 2;
            int teeEnforcedPurposeValue = 2;
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // purpose tag is 1
            var keyDescription = Asn1Element.Decode(attExtBytes);
            var softwareEnforced = keyDescription[6].Sequence;

            foreach (Asn1Element s in softwareEnforced)
            {
                switch (s.TagValue)
                {
                    case 1:
                        softwareEnforcedPurposeValue = s[0][0].GetInt32();
                        break;
                    default:
                        break;
                }
            }

            var teeEnforced = keyDescription[7].Sequence;
            foreach (Asn1Element s in teeEnforced)
            {
                switch (s.TagValue)
                {
                    case 1:
                        teeEnforcedPurposeValue = s[0][0].GetInt32();
                        break;
                    default:
                        break;
                }
            }

            return (softwareEnforcedPurposeValue is 2 && teeEnforcedPurposeValue is 2);
        }

        public override (AttestationType, X509Certificate2[]) Verify()
        {
            // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields
            // (handled in base class)
            if (attStmt.Keys.Count is 0 || attStmt.Values.Count is 0)
                throw new Fido2VerificationException("Attestation format android-key must have attestation statement");

            if (Sig is null || Sig.Type != CBORType.ByteString || Sig.GetByteString().Length is 0)
                throw new Fido2VerificationException("Invalid android-key attestation signature");

            // 2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
            // using the attestation public key in attestnCert with the algorithm specified in alg
            if (X5c is null || X5c.Type != CBORType.Array || X5c.Count is 0)
                throw new Fido2VerificationException("Malformed x5c in android-key attestation");

            if (X5c.Values is null || X5c.Values.Count is 0 ||
                X5c.Values.First().Type != CBORType.ByteString ||
                X5c.Values.First().GetByteString().Length is 0)
            {
                throw new Fido2VerificationException("Malformed x5c in android-key attestation");
            }

            X509Certificate2 androidKeyCert;
            ECDsa androidKeyPubKey;
            try
            {
                androidKeyCert = new X509Certificate2(X5c.Values.First().GetByteString());
                androidKeyPubKey = androidKeyCert.GetECDsaPublicKey()!; // attestation public key
            }
            catch (Exception ex)
            {
                throw new Fido2VerificationException("Failed to extract public key from android key: " + ex.Message, ex);
            }

            if (Alg is null || !Alg.IsNumber)
                throw new Fido2VerificationException("Invalid android key attestation algorithm");

            byte[] ecsig;
            try
            {
                ecsig = CryptoUtils.SigFromEcDsaSig(Sig.GetByteString(), androidKeyPubKey.KeySize);
            }
            catch (Exception ex)
            {
                throw new Fido2VerificationException("Failed to decode android key attestation signature from ASN.1 encoded form", ex);
            }

            if (!androidKeyPubKey.VerifyData(Data, ecsig, CryptoUtils.HashAlgFromCOSEAlg((COSE.Algorithm)Alg.AsInt32())))
                throw new Fido2VerificationException("Invalid android key attestation signature");

            // 3. Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
            if (!AuthData.AttestedCredentialData.CredentialPublicKey.Verify(Data, Sig.GetByteString()))
                throw new Fido2VerificationException("Incorrect credentialPublicKey in android key attestation");

            // 4. Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash
            var attExtBytes = AttestationExtensionBytes(androidKeyCert.Extensions);
            if (attExtBytes is null)
                throw new Fido2VerificationException("Android key attestation certificate contains no AttestationRecord extension");

            try
            {
                var attestationChallenge = GetAttestationChallenge(attExtBytes);
                if (!clientDataHash.AsSpan().SequenceEqual(attestationChallenge))
                    throw new Fido2VerificationException("Mismatch between attestationChallenge and hashedClientDataJson verifying android key attestation certificate extension");
            }
            catch (Exception)
            {
                throw new Fido2VerificationException("Malformed android key AttestationRecord extension verifying android key attestation certificate extension");
            }

            // 5. Verify the following using the appropriate authorization list from the attestation certificate extension data

            // 5a. The AuthorizationList.allApplications field is not present, since PublicKeyCredential MUST be bound to the RP ID
            if (FindAllApplicationsField(attExtBytes))
                throw new Fido2VerificationException("Found all applications field in android key attestation certificate extension");

            // 5bi. The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED ( which == 0).
            if (!IsOriginGenerated(attExtBytes))
                throw new Fido2VerificationException("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension");

            // 5bii. The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN (which == 2).
            if (!IsPurposeSign(attExtBytes))
                throw new Fido2VerificationException("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension");

            var trustPath = X5c.Values
                .Select(x => new X509Certificate2(x.GetByteString()))
                .ToArray();

            return (AttestationType.Basic, trustPath);
        }
    }
}
