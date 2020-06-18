using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Asn1;
using PeterO.Cbor;

namespace Fido2NetLib.AttestationFormat
{
    internal class AndroidKey : AttestationFormat
    {
        public AndroidKey(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash) : base(attStmt, authenticatorData, clientDataHash)
        {
        }

        public static byte[] AttestationExtensionBytes(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.11129.2.1.17")) // AttestationRecordOid
                {
                    return ext.RawData;
                }
            }
            return null;
        }

        public static byte[] GetAttestationChallenge(byte[] attExtBytes)
        {
            var keyDescription = AsnElt.Decode(attExtBytes);
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // attestationChallenge at index 4
            return keyDescription.GetSub(4).GetOctetString();
        }

        public static bool FindAllApplicationsField(byte[] attExtBytes)
        {
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // check both software and tee enforced AuthorizationList objects for presense of "allApplications" tag, number 600
            var keyDescription = AsnElt.Decode(attExtBytes);

            var softwareEnforced = keyDescription.GetSub(6).Sub;
            foreach (AsnElt s in softwareEnforced)
            {
                switch (s.TagValue)
                {
                    case 600:
                        return true;
                    default:
                        break;
                }
            }

            var teeEnforced = keyDescription.GetSub(7).Sub;
            foreach (AsnElt s in teeEnforced)
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
            long softwareEnforcedOriginValue = 0;
            long teeEnforcedOriginValue = 0;
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // origin tag is 702
            var keyDescription = AsnElt.Decode(attExtBytes);
            var softwareEnforced = keyDescription.GetSub(6).Sub;
            foreach (AsnElt s in softwareEnforced)
            {
                switch (s.TagValue)
                {
                    case 702:
                        softwareEnforcedOriginValue = s.Sub[0].GetInteger();
                        break;
                    default:
                        break;
                }
            }
            
            var teeEnforced = keyDescription.GetSub(7).Sub;
            foreach (AsnElt s in teeEnforced)
            {
                switch (s.TagValue)
                {
                    case 702:
                        teeEnforcedOriginValue = s.Sub[0].GetInteger();
                        break;
                    default:
                        break;
                }
            }
            
            return (0 == softwareEnforcedOriginValue && 0 == teeEnforcedOriginValue);
        }

        public static bool IsPurposeSign(byte[] attExtBytes)
        {
            long softwareEnforcedPurposeValue = 2;
            long teeEnforcedPurposeValue = 2;
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // purpose tag is 1
            var keyDescription = AsnElt.Decode(attExtBytes);
            var softwareEnforced = keyDescription.GetSub(6).Sub;
            foreach (AsnElt s in softwareEnforced)
            {
                switch (s.TagValue)
                {
                    case 1:
                        softwareEnforcedPurposeValue = s.Sub[0].Sub[0].GetInteger();
                        break;
                    default:
                        break;
                }
            }

            var teeEnforced = keyDescription.GetSub(7).Sub;
            foreach (AsnElt s in teeEnforced)
            {
                switch (s.TagValue)
                {
                    case 1:
                        teeEnforcedPurposeValue = s.Sub[0].Sub[0].GetInteger();
                        break;
                    default:
                        break;
                }
            }

            return (2 == softwareEnforcedPurposeValue && 2 == teeEnforcedPurposeValue);
        }

        public override void Verify()
        {
            // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields
            // (handled in base class)
            if (0 == attStmt.Keys.Count || 0 == attStmt.Values.Count)
                throw new Fido2VerificationException("Attestation format android-key must have attestation statement");

            if (null == Sig || CBORType.ByteString != Sig.Type || 0 == Sig.GetByteString().Length)
                throw new Fido2VerificationException("Invalid android-key attestation signature");
            // 2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
            // using the attestation public key in attestnCert with the algorithm specified in alg
            if (null == X5c || CBORType.Array != X5c.Type || 0 == X5c.Count)
                throw new Fido2VerificationException("Malformed x5c in android-key attestation");

            if (null == X5c.Values || 0 == X5c.Values.Count ||
                CBORType.ByteString != X5c.Values.First().Type ||
                0 == X5c.Values.First().GetByteString().Length)
                throw new Fido2VerificationException("Malformed x5c in android-key attestation");

            X509Certificate2 androidKeyCert;
            ECDsa androidKeyPubKey;
            try
            {
                androidKeyCert = new X509Certificate2(X5c.Values.First().GetByteString());
                androidKeyPubKey = androidKeyCert.GetECDsaPublicKey(); // attestation public key
            }
            catch (Exception ex)
            {
                throw new Fido2VerificationException("Failed to extract public key from android key: " + ex.Message, ex);
            }

            if (null == Alg || true != Alg.IsNumber || false == CryptoUtils.algMap.ContainsKey(Alg.AsInt32()))
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

            if (true != androidKeyPubKey.VerifyData(Data, ecsig, CryptoUtils.algMap[Alg.AsInt32()]))
                throw new Fido2VerificationException("Invalid android key attestation signature");

            // 3. Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
            if (true != AuthData.AttestedCredentialData.CredentialPublicKey.Verify(Data, Sig.GetByteString()))
                throw new Fido2VerificationException("Incorrect credentialPublicKey in android key attestation");

            // 4. Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash
            var attExtBytes = AttestationExtensionBytes(androidKeyCert.Extensions);
            if (null == attExtBytes)
                throw new Fido2VerificationException("Android key attestation certificate contains no AttestationRecord extension");

            try
            {
                var attestationChallenge = GetAttestationChallenge(attExtBytes);
                if (false == clientDataHash.SequenceEqual(attestationChallenge))
                    throw new Fido2VerificationException("Mismatch between attestationChallenge and hashedClientDataJson verifying android key attestation certificate extension");
            }
            catch (Exception)
            {
                throw new Fido2VerificationException("Malformed android key AttestationRecord extension verifying android key attestation certificate extension");
            }

            // 5. Verify the following using the appropriate authorization list from the attestation certificate extension data

            // 5a. The AuthorizationList.allApplications field is not present, since PublicKeyCredential MUST be bound to the RP ID
            if (true == FindAllApplicationsField(attExtBytes))
                throw new Fido2VerificationException("Found all applications field in android key attestation certificate extension");

            // 5bi. The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED ( which == 0).
            if (false == IsOriginGenerated(attExtBytes))
                throw new Fido2VerificationException("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension");

            // 5bii. The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN (which == 2).
            if (false == IsPurposeSign(attExtBytes))
                throw new Fido2VerificationException("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension");
        }
    }
}
