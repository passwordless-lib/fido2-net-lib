using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

        public static byte[] GetASN1ObjectAtIndex(byte[] attExtBytes, int index)
        {
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // This function returns an entry from the KeyDescription at index
            if (null == attExtBytes || 0 == attExtBytes.Length || attExtBytes.Length > ushort.MaxValue)
                throw new Fido2VerificationException("Invalid attExtBytes signature value");
            var offset = 0;
            var derSequence = AuthDataHelper.GetSizedByteArray(attExtBytes, ref offset, 1);

            // expecting to start with 0x30 indicating SEQUENCE
            if (null == derSequence || 0x30 != derSequence[0])
                throw new Fido2VerificationException("attExtBytes signature not a valid DER sequence");

            // next is length of all the items in the sequence
            var dataLen = AuthDataHelper.GetSizedByteArray(attExtBytes, ref offset, 1);
            if (null == dataLen)
                throw new Fido2VerificationException("attExtBytes signature has invalid length");

            // if data is more than 127 bytes, the length is encoded in long form
            // TODO : Why is longLen never used ?
            var longForm = (dataLen[0] > 0x7f);
            var longLen = 0;
            if (true == longForm)
            {
                var longLenByte = AuthDataHelper.GetSizedByteArray(attExtBytes, ref offset, 1);
                if (null == longLenByte)
                    throw new Fido2VerificationException("attExtBytes signature has invalid long form length");
                longLen = longLenByte[0];
                longLen &= (1 << 7);
            }

            // walk through each sequence entry until we get to the requested index
            for (var i = 0; i < index; i++)
            {
                var derId = AuthDataHelper.GetSizedByteArray(attExtBytes, ref offset, 1);
                if (null == derId)
                    throw new Fido2VerificationException("Ran out of bytes in attExtBytes sequence without finding the first octet string");
                var lenValue = AuthDataHelper.GetSizedByteArray(attExtBytes, ref offset, 1);
                if (null == lenValue)
                    throw new Fido2VerificationException("attExtBytes lenValue invalid");
                if (0 < lenValue[0])
                {
                    var value = AuthDataHelper.GetSizedByteArray(attExtBytes, ref offset, lenValue[0]);
                    if (null == value)
                        throw new Fido2VerificationException("Ran out of bytes in attExtBytes sequence without finding the first octet string");
                }
            }
            // skip the identifier of the requested item
            var asn1Id = AuthDataHelper.GetSizedByteArray(attExtBytes, ref offset, 1);
            if (null == asn1Id)
                throw new Fido2VerificationException("Ran out of bytes in attExtBytes sequence without finding the first octet string");
            // get length of requested item
            var lenAsn1value = AuthDataHelper.GetSizedByteArray(attExtBytes, ref offset, 1);
            if (null == lenAsn1value)
                throw new Fido2VerificationException("lenAttestationChallenge version length invalid");
            // return byte array containing the requested item
            return AuthDataHelper.GetSizedByteArray(attExtBytes, ref offset, lenAsn1value[0]);
        }

        public static byte[] GetAttestationChallenge(byte[] attExtBytes)
        {
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // attestationChallenge at index 4
            return GetASN1ObjectAtIndex(attExtBytes, 4);
        }

        public static byte[] GetSoftwareEnforcedAuthorizationList(byte[] attExtBytes)
        {
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // softwareEnforced AuthorizationList at index 6
            return GetASN1ObjectAtIndex(attExtBytes, 6);
        }

        public static byte[] GetTeeEnforcedAuthorizationList(byte[] attExtBytes)
        {
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // teeEnforced AuthorizationList at index 7
            return GetASN1ObjectAtIndex(attExtBytes, 7);
        }

        public static bool FindAllApplicationsField(byte[] attExtBytes)
        {
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // check both software and tee enforced AuthorizationList objects for presense of "allApplications" tag, number 600
            var software = GetSoftwareEnforcedAuthorizationList(attExtBytes);
            var tee = GetTeeEnforcedAuthorizationList(attExtBytes);
            var ignore = -1;
            // allApplications is tag 600, and should not be found in either list
            return (GetDERTagValue(software, 600, ref ignore) && GetDERTagValue(tee, 600, ref ignore));
        }

        public static bool GetDERTagValue(byte[] authList, int tag, ref int result)
        {
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // walk authorizationList sequence looking for an item with requested tag
            // if tag is found, return true and set the result value to the found int value
            // the only two items we are expecting to find are purpose and origin
            // which are set of integer or integer, so int result is ok for now
            // if entire list is walked and tag is not found, return false
            for (var i = 0; i < authList.Length;)
            {
                // expecting to see first byte indicting the attribute is of class 2, and constructed value
                // first two bits are the class, expecting to see 10
                // third bit is primative (0) or constructed (1)
                if (false == ((authList[i] & 0xA0) == 0xA0))
                    throw new Fido2VerificationException("Expected class 2 constructed ASN.1 value");

                int foundTag;
                // if the tag value is below 0x1F (11111), the value is stored in the remaining 5 bits of the first byte 
                if (false == ((authList[i] & 0x1F) == 0x1F))
                {
                    foundTag = (authList[i] & ~0xA0);
                    i++;
                }
                // otherwise, if the tag value is 0x3FFF (11111111111111) or below
                // the value is stored in the lower 7 bits of the second byte, and the lower 7 bits of the third byte
                // this is signified by the high order bit set in the second byte, but not set in the third byte
                else if (((authList[i + 1] & 0x80) == 0x80) && ((authList[i + 2] & 0x80) == 0x0))
                {
                    // take the lower 7 bits in the second byte, shift them left 7 positions
                    // then add the lower 7 bits of the third byte to get the tag value
                    // Welcome to Abstract Syntax Notation One
                    foundTag = ((authList[i + 1] & ~0x80) << 7) + (authList[i + 2]);
                    i += 3;
                }
                else
                {
                    throw new Fido2VerificationException("Expecting ASN.1 tag less than 0x3FFF");
                }
                // if the tag we found is the one that we are looking for, get the value
                if (tag == foundTag)
                {
                    // 5 bytes will be remaining if this a set (0x31), advance to the integer
                    if (5 == authList[i] && 0x31 == authList[i + 1])
                        i += 2;
                    // for our purposes, we should see that there are 3 bytes remaining after this one
                    // the second byte should be 2 indicating the value is an integer
                    // and the third byte is the length in bytes, which again, for our purposes, should be one 
                    if (3 == authList[i] && 2 == authList[i + 1] && 1 == authList[i + 2])
                    {
                        // value is stored in the 4th byte, no need to go any further, we have our result
                        result = authList[i + 3];
                        return true;
                    }
                    else
                    {
                        throw new Fido2VerificationException("Unexpected byte sequence found fetching ASN.1 integer value");
                    }
                }

                // if we didn't find the tag we were looking for, advance the index
                // by the the size in bytes of the current tag plus one byte for the size
                else if (i < authList.Length)
                {
                    i += authList[i] + 1;
                }
            }
            // ran out of bytes without finding the tag we were looking for
            return false;
        }

        public static bool IsOriginGenerated(byte[] attExtBytes)
        {
            var tagValue = -1;
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // origin tag is 702
            var result = GetDERTagValue(GetTeeEnforcedAuthorizationList(attExtBytes), 702, ref tagValue);
            return (0 == tagValue && true == result);
        }

        public static bool IsPurposeSign(byte[] attExtBytes)
        {
            var tagValue = -1;
            // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
            // purpose tag is 1
            var result = GetDERTagValue(GetTeeEnforcedAuthorizationList(attExtBytes), 1, ref tagValue);
            return (2 == tagValue && true == result);
        }

        public override void Verify()
        {
            // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields
            if (0 == attStmt.Keys.Count || 0 == attStmt.Values.Count)
                throw new Fido2VerificationException("Attestation format packed must have attestation statement");

            if (null == Sig || CBORType.ByteString != Sig.Type || 0 == Sig.GetByteString().Length)
                throw new Fido2VerificationException("Invalid packed attestation signature");
            // 2a. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
            // using the attestation public key in attestnCert with the algorithm specified in alg
            if (null == X5c && CBORType.Array != X5c.Type && 0 == X5c.Count)
                throw new Fido2VerificationException("Malformed x5c in android-key attestation");

            if (null == X5c.Values || 0 == X5c.Values.Count ||
                CBORType.ByteString != X5c.Values.First().Type ||
                0 == X5c.Values.First().GetByteString().Length)
                throw new Fido2VerificationException("Malformed x5c in android-key attestation");

            X509Certificate2 androidKeyCert;
            ECDsaCng androidKeyPubKey;
            try
            {
                androidKeyCert = new X509Certificate2(X5c.Values.First().GetByteString());
                androidKeyPubKey = (ECDsaCng)androidKeyCert.GetECDsaPublicKey(); // attestation public key
            }
            catch (Exception ex)
            {
                throw new Fido2VerificationException("Failed to extract public key from android key: " + ex.Message, ex);
            }

            if (null == Alg || CBORType.Number != Alg.Type || false == CryptoUtils.algMap.ContainsKey(Alg.AsInt32()))
                throw new Fido2VerificationException("Invalid attestation algorithm");
            if (true != androidKeyPubKey.VerifyData(Data,
                                                    CryptoUtils.SigFromEcDsaSig(Sig.GetByteString(), androidKeyPubKey.KeySize),
                                                    CryptoUtils.algMap[Alg.AsInt32()]))
                throw new Fido2VerificationException("Invalid android key signature");

            // Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
            if (true != AuthData.AttestedCredentialData.CredentialPublicKey.Verify(Data, Sig.GetByteString()))
                throw new Fido2VerificationException("Invalid android key signature");

            // Verify that in the attestation certificate extension data:
            var attExtBytes = AttestationExtensionBytes(androidKeyCert.Extensions);

            // 1. The value of the attestationChallenge field is identical to clientDataHash.
            var attestationChallenge = GetAttestationChallenge(attExtBytes);
            if (false == clientDataHash.SequenceEqual(attestationChallenge))
                throw new Fido2VerificationException("Mismatched between attestationChallenge and hashedClientDataJson verifying android key attestation certificate extension");

            // 2. The AuthorizationList.allApplications field is not present, since PublicKeyCredential MUST be bound to the RP ID.
            if (true == FindAllApplicationsField(attExtBytes))
                throw new Fido2VerificationException("Found all applications field in android key attestation certificate extension");

            // 3. The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED ( which == 0).
            if (false == IsOriginGenerated(attExtBytes))
                throw new Fido2VerificationException("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension");

            // 4. The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN (which == 2).
            if (false == IsPurposeSign(attExtBytes))
                throw new Fido2VerificationException("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension");
        }
    }
}
