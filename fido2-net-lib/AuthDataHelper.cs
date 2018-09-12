using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Fido2NetLib
{
    /// <summary>
    /// Helper functions that implements https://w3c.github.io/webauthn/#authenticator-data
    /// </summary>
    public static class AuthDataHelper
    {
        public static HashAlgorithm GetHasher(HashAlgorithmName hashName)
        {
            switch (hashName.Name)
            {
                case "SHA1":
                    return SHA1.Create();
                case "SHA256":
                    return SHA256.Create();
                case "SHA384":
                    return SHA384.Create();
                case "SHA512":
                    return SHA512.Create();
                default:
                    throw new ArgumentOutOfRangeException("hashName");
            }
        }

        public static readonly Dictionary<int, HashAlgorithmName> algMap = new Dictionary<int, HashAlgorithmName>
        {
            {-65535, HashAlgorithmName.SHA1 },
            {-7, HashAlgorithmName.SHA256},
            {-35, HashAlgorithmName.SHA384 },
            {-36, HashAlgorithmName.SHA512 },
            {-37, HashAlgorithmName.SHA256 },
            {-38, HashAlgorithmName.SHA384 },
            {-39, HashAlgorithmName.SHA512 },
            {-257, HashAlgorithmName.SHA256 },
            {-258, HashAlgorithmName.SHA384 },
            {-259, HashAlgorithmName.SHA512 },
            {4, HashAlgorithmName.SHA1 },
            {11, HashAlgorithmName.SHA256 },
            {12, HashAlgorithmName.SHA384 },
            {13, HashAlgorithmName.SHA512 }
        };

        public static bool VerifySigWithCoseKey(byte[] data, PeterO.Cbor.CBORObject coseKey, byte[] sig)
        {
            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData
            var kty = coseKey[PeterO.Cbor.CBORObject.FromObject(1)].AsInt32();
            var alg = coseKey[PeterO.Cbor.CBORObject.FromObject(3)].AsInt32();
            var crv = 0;
            if (1 == kty || 2 == kty) crv = coseKey[PeterO.Cbor.CBORObject.FromObject(-1)].AsInt32();
            switch (kty) // https://www.iana.org/assignments/cose/cose.xhtml#key-type
            {
                case 1: // OKP
                    {
                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                        {
                            case -8:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case 6:
                                        throw new Fido2VerificationException("ALG_SIGN_ED25519_EDDSA_SHA512_RAW support not yet implmented");
                                    default:
                                        throw new ArgumentOutOfRangeException("crv");
                                }
                            default:
                                throw new ArgumentOutOfRangeException("alg");
                        }
                    }
                case 2: // EC2
                    {
                        var point = new ECPoint
                        {
                            X = coseKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString(),
                            Y = coseKey[PeterO.Cbor.CBORObject.FromObject(-3)].GetByteString()
                        };
                        ECCurve curve;
                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                        {
                            case -7:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case 1:
                                    case 8:
                                        curve = ECCurve.NamedCurves.nistP256;
                                        break;
                                    default:
                                        throw new ArgumentOutOfRangeException("crv");
                                }
                                break;
                            case -35:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case 2:
                                        curve = ECCurve.NamedCurves.nistP384;
                                        break;
                                    default:
                                        throw new ArgumentOutOfRangeException("crv");
                                }
                                break;
                            case -36:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case 3:
                                        curve = ECCurve.NamedCurves.nistP521;
                                        System.Diagnostics.Debug.WriteLine(BitConverter.ToString(sig).Replace("-", ""));
                                        break;
                                    default:
                                        throw new ArgumentOutOfRangeException("crv");
                                }
                                break;
                            default:
                                throw new ArgumentOutOfRangeException("alg");
                        }
                        var cng = ECDsaCng.Create(new ECParameters
                        {
                            Q = point,
                            Curve = curve
                        });
                        var ecsig = SigFromEcDsaSig(sig);
                        System.Diagnostics.Debug.WriteLine(BitConverter.ToString(ecsig).Replace("-", ""));
                        return cng.VerifyData(data, ecsig, algMap[alg]);
                    }
                case 3: // RSA
                    {
                        RSACng rsa = new RSACng();
                        rsa.ImportParameters(
                            new RSAParameters()
                            {
                                Modulus = coseKey[PeterO.Cbor.CBORObject.FromObject(-1)].GetByteString(),
                                Exponent = coseKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString()
                            }
                        );
                        RSASignaturePadding padding;
                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                    {

                            case -37:
                            case -38:
                            case -39:
                                padding = RSASignaturePadding.Pss;
                                break;

                            case -65535:
                            case -257:
                            case -258:
                            case -259:
                                padding = RSASignaturePadding.Pkcs1;
                                break;
                            default:
                                throw new ArgumentOutOfRangeException("alg");
                        }
                        return rsa.VerifyData(data, sig, algMap[alg], padding);
                    }
            }
            throw new Fido2VerificationException("Missing or unknown keytype");
        }
        public static byte[] AaguidFromAttnCertExts(X509ExtensionCollection exts)
        {
            byte[] aaguid = null;
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.1.1.4")) // id-fido-gen-ce-aaguid
                {
                    aaguid = new byte[16];
                    var ms = new System.IO.MemoryStream(ext.RawData.ToArray());
                    // OCTET STRING
                    if (0x4 != ms.ReadByte()) throw new Fido2VerificationException("Expected octet string value");
                    // AAGUID
                    if (0x10 != ms.ReadByte()) throw new Fido2VerificationException("Unexpected length for aaguid");
                    ms.Read(aaguid, 0, 0x10);
                    //The extension MUST NOT be marked as critical
                    if (true == ext.Critical) throw new Fido2VerificationException("extension MUST NOT be marked as critical");
                }
            }
            return aaguid;
        }
        public static string SANFromAttnCertExts(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.17")) // subject alternative name
                {
                    var asn = new AsnEncodedData(ext.Oid, ext.RawData);
                    return asn.Format(true);
                }
            }
            return null;
        }
        public static string EKUFromAttnCertExts(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.37")) // EKU
                {
                    var asn = new AsnEncodedData(ext.Oid, ext.RawData);
                    return asn.Format(false);
                }
            }
            return null;
        }
        public static bool IsAttnCertCACert(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.FriendlyName == "Basic Constraints")
                {
                    X509BasicConstraintsExtension baseExt = (X509BasicConstraintsExtension)ext;
                    return baseExt.CertificateAuthority;
                }
            }
            return true;
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

        public static int U2FTransportsFromAttnCert(X509ExtensionCollection exts)
        {
            var u2ftransports = 0;
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.2.1.1"))
                {
                    var ms = new System.IO.MemoryStream(ext.RawData.ToArray());
                    // BIT STRING
                    if (0x3 != ms.ReadByte()) throw new Fido2VerificationException("Expected bit string");
                    if (0x2 != ms.ReadByte()) throw new Fido2VerificationException("Expected integer value");
                    var unused = ms.ReadByte(); // unused byte
                    // https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-authenticator-transports-extension-v1.1-id-20160915.html#fido-u2f-certificate-transports-extension
                    u2ftransports = ms.ReadByte(); // do something with this?
                }
            }
            return u2ftransports;
        }

        public static bool IsValidPackedAttnCertSubject(string attnCertSubj)
        {
            var dictSubject = attnCertSubj.Split(new string[] { ", " }, StringSplitOptions.None).Select(part => part.Split('=')).ToDictionary(split => split[0], split => split[1]);
            return (0 != dictSubject["C"].Length ||
                0 != dictSubject["O"].Length ||
                0 != dictSubject["OU"].Length ||
                0 != dictSubject["CN"].Length ||
                "Authenticator Attestation" == dictSubject["OU"].ToString());
        }

        public static Memory<byte> U2FKeyFromCOSEKey(PeterO.Cbor.CBORObject COSEKey)
        {
            var x = COSEKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString();
            var y = COSEKey[PeterO.Cbor.CBORObject.FromObject(-3)].GetByteString();
            var publicKeyU2F = new byte[1] { 0x4 }; // uncompressed
            return  publicKeyU2F.Concat(x).Concat(y).ToArray();
        }

        public static byte[] GetSizedByteArray(Memory<byte> ab, ref int offset, UInt16 len = 0)
        {
            if ((0 == len) && ((offset + 2) <= ab.Length))
            {
                len = BitConverter.ToUInt16(ab.Slice(offset, 2).ToArray().Reverse().ToArray(), 0);
                offset += 2;
            }
            byte[] result = null;
            if ((0 < len) && ((offset + len) <= ab.Length)) 
            {
                result = ab.Slice(offset, len).ToArray();
                offset += len;
            }
            return result;
        }
        public static byte[] GetASN1ObjectAtIndex(byte[] attExtBytes, int index)
        {
            System.Diagnostics.Debug.WriteLine(BitConverter.ToString(attExtBytes).Replace("-", ""));
            if (null == attExtBytes || 0 == attExtBytes.Length || attExtBytes.Length > Math.Pow(2, 1008)) throw new Fido2VerificationException("Invalid attExtBytes signature value");
            var offset = 0;
            var derSequence = GetSizedByteArray(attExtBytes, ref offset, 1);
            if (null == derSequence || 0x30 != derSequence[0]) throw new Fido2VerificationException("attExtBytes signature not a valid DER sequence");
            var dataLen = GetSizedByteArray(attExtBytes, ref offset, 1);
            if (null == dataLen) throw new Fido2VerificationException("attExtBytes signature has invalid length");
            var longForm = (dataLen[0] > 0x7f);
            var longLen = 0;
            if (true == longForm)
            {
                var longLenByte = GetSizedByteArray(attExtBytes, ref offset, 1);
                if (null == longLenByte) throw new Fido2VerificationException("attExtBytes signature has invalid long form length");
                longLen = longLenByte[0];
                longLen &= (1 << 7);
            }
            
            for (var i = 0; i < index; i++)
            {
                var derId = GetSizedByteArray(attExtBytes, ref offset, 1);
                if (null == derId) throw new Fido2VerificationException("Ran out of bytes in attExtBytes sequence without finding the first octet string");
                var lenValue = GetSizedByteArray(attExtBytes, ref offset, 1);
                if (null == lenValue) throw new Fido2VerificationException("attExtBytes lenValue invalid");
                if (0 < lenValue[0])
                {
                    var value = GetSizedByteArray(attExtBytes, ref offset, lenValue[0]);
                    if (null == value) throw new Fido2VerificationException("Ran out of bytes in attExtBytes sequence without finding the first octet string");
                }
            }

            var asn1Id = GetSizedByteArray(attExtBytes, ref offset, 1);
            if (null == asn1Id) throw new Fido2VerificationException("Ran out of bytes in attExtBytes sequence without finding the first octet string");
            var lenAsn1value = GetSizedByteArray(attExtBytes, ref offset, 1);
            if (null == lenAsn1value) throw new Fido2VerificationException("lenAttestationChallenge version length invalid");
            return GetSizedByteArray(attExtBytes, ref offset, lenAsn1value[0]);
        }
        public static byte[] GetAttestationChallenge(byte[] attExtBytes)
        {
            // skip attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel
            return GetASN1ObjectAtIndex(attExtBytes, 4);
        }
        public static byte[] GetSoftwareEnforcedAuthorizationList(byte[] attExtBytes)
        {
            return GetASN1ObjectAtIndex(attExtBytes, 6);
        }
        public static byte[] GetTeeEnforcedAuthorizationList(byte[] attExtBytes)
        {
            return GetASN1ObjectAtIndex(attExtBytes, 7);
        }

        public static bool FindAllApplicationsField(byte[] attExtBytes)
        {
            var software = GetSoftwareEnforcedAuthorizationList(attExtBytes);
            var tee = GetTeeEnforcedAuthorizationList(attExtBytes);
            var ignore = -1;
            return (GetDERTagValue(software, 600, ref ignore) && GetDERTagValue(tee, 600, ref ignore));
        }
        public static bool GetDERTagValue(byte[] authList, int tag, ref int result)
        {
            for (int i = 0; i < authList.Length;)
            {
                var Class2Constructed = (authList[i] & 0xA0) == 0xA0;
                var Full = (authList[i] & 0x1F) == 0x1F;
                var FoundTag = 0;
                if (false == Full)
                {
                    FoundTag = (authList[i] &~ 0xA0);
                    i++;
                }
                else
                {
                    FoundTag = ((authList[i + 1] & ~0x80) << 7) + (authList[i + 2]);
                    i += 3;
                }
                if (tag == FoundTag)
                {
                    if (5 == authList[i] && 0x31 == authList[i + 1]) i += 2;
                    if (3 == authList[i] && 2 == authList[i + 1] && 1 == authList[i + 2])
                    {
                        result = authList[i + 3];
                        return true;
                    }
                }
                else if (i < authList.Length) i += authList[i] + 1;
            }
            return false;
        }

        public static bool IsOriginGenerated(byte[] attExtBytes)
        {
            var tagValue = -1;
            var result = GetDERTagValue(GetTeeEnforcedAuthorizationList(attExtBytes), 702, ref tagValue);
            return (0 == tagValue && true == result);
        }
        public static bool IsPurposeSign(byte[] attExtBytes)
        {
            var tagValue = -1;
            var result = GetDERTagValue(GetTeeEnforcedAuthorizationList(attExtBytes), 1, ref tagValue);
            return (2 == tagValue && true == result);
        }
        public static byte[] GetEcDsaSigValue(byte[] ecDsaSig, ref int offset, bool longForm)
        {
            var derInt = GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == derInt || 0x02 != derInt[0]) throw new Fido2VerificationException("ECDsa signature coordinate sequence does not contain DER integer value"); // DER INTEGER
            var lenByte = GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == lenByte) throw new Fido2VerificationException("ECDsa signature coordinate integer size invalid");
            var len = (UInt16) lenByte[0];
            if (false == longForm)
            {
                /*
                 *  Ecdsa-Sig-Value  ::=  SEQUENCE  {
                 *       r     INTEGER,
                 *       s     INTEGER  } 
                 *       
                 *  From: https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-integer
                 *  
                 *  "Integer values are encoded into a TLV triplet that begins with a Tag value of 0x02. 
                 *  The Value field of the TLV triplet contains the encoded integer if it is positive, 
                 *  or its two's complement if it is negative. If the integer is positive but the high 
                 *  order bit is set to 1, a leading 0x00 is added to the content to indicate that the
                 *  number is not negative."
                 *  
                 */
                if (0x00 == ecDsaSig[offset] && ((ecDsaSig[offset + 1] & (1 << 7)) != 0))
                {
                    offset++;
                    len--;
                }
            }
            return GetSizedByteArray(ecDsaSig, ref offset, len);
        }
        public static byte[] SigFromEcDsaSig(byte[] ecDsaSig)
        {
            // sanity check of input data
            if (null == ecDsaSig || 0 == ecDsaSig.Length || ecDsaSig.Length > UInt16.MaxValue) throw new Fido2VerificationException("Invalid ECDsa signature value");
            // first byte should be DER sequence marker
            var offset = 0;
            var derSequence = GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == derSequence || 0x30 != derSequence[0]) throw new Fido2VerificationException("ECDsa signature not a valid DER sequence");
            // two forms of length, short form and long form
            // short form, one byte, bit 8 not set, rest of the bits indicate data length
            var dataLen = GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == dataLen) throw new Fido2VerificationException("ECDsa signature has invalid length");
            // long form, first byte, bit 8 is set, rest of bits indicate the length of the data length
            // so if bit 8 is on...
            var longForm = (0 != (dataLen[0] & (1 << 7)));
            if (true == longForm)
            {
                // rest of bits indicate the length of the data length
                var longLen = (dataLen[0] & ~(1 << 7));
                // sanity check of input data
                if (UInt16.MinValue > longLen || UInt16.MaxValue < longLen) throw new Fido2VerificationException("ECDsa signature has invalid long form length");
                // total length of remaining data
                var longLenByte = GetSizedByteArray(ecDsaSig, ref offset, (UInt16) longLen);
                if (null == longLenByte) throw new Fido2VerificationException("ECDsa signature has invalid long form length");
                longLen = (UInt16)longLenByte[0];
                // sanity check the length
                if (ecDsaSig.Length != (offset + longLen)) throw new Fido2VerificationException("ECDsa signature has invalid long form length");
            }

            // Get R value
            var r = GetEcDsaSigValue(ecDsaSig, ref offset, longForm);
            if (null == r) throw new Fido2VerificationException("ECDsa signature R integer value invalid");
            
            // Get S value
            var s = GetEcDsaSigValue(ecDsaSig, ref offset, longForm);
            if (null == s) throw new Fido2VerificationException("ECDsa signature S integer value invalid");

            // make sure we are at the end
            if (ecDsaSig.Length != offset) throw new Fido2VerificationException("ECDsa signature has bytes leftover after parsing R and S values");

            // combine the coordinates and return the raw sign
            var sig = new byte[s.Length + r.Length];
            Buffer.BlockCopy(r, 0, sig, 0, r.Length);
            Buffer.BlockCopy(s, 0, sig, r.Length, s.Length);
            return sig;
        }
    }
        // https://w3c.github.io/webauthn/#authenticator-data
    public class AuthenticatorData
    {
        enum authDataFlags
        {
            UP,
            RFU1,
            UV,
            RFU2,
            RFU3,
            RFU4,
            AT,
            ED
        }
        public AuthenticatorData(byte[] authData)
        {
            if (null == authData || authData.Length < 37) throw new Fido2VerificationException("Authenticator data is invalid");
            var offset = 0;
            RpIdHash = AuthDataHelper.GetSizedByteArray(authData, ref offset, 32);
            Flags = AuthDataHelper.GetSizedByteArray(authData, ref offset, 1)[0];
            SignCount = AuthDataHelper.GetSizedByteArray(authData, ref offset, 4);
            if (false == AttestedCredentialDataPresent && false == ExtensionsPresent && 37 != authData.Length) throw new Fido2VerificationException("Authenticator data flags and data mismatch");
            AttData = null;
            Extensions = null;
            // Determining attested credential data's length, which is variable, involves determining credentialPublicKey’s beginning location given the preceding credentialId’s length, and then determining the credentialPublicKey’s length
            if (true == AttestedCredentialDataPresent) AttData = new AttestedCredentialData(authData, ref offset);
            if (true == ExtensionsPresent) Extensions = AuthDataHelper.GetSizedByteArray(authData, ref offset, (UInt16) (authData.Length - offset));
            if (authData.Length != offset) throw new Fido2VerificationException("Leftover bytes decoding AuthenticatorData");
        }
        public byte[] RpIdHash { get; private set; }
        public byte Flags { get; private set; }
        public byte[] SignCount { get; private set; }
        public AttestedCredentialData AttData { get; private set; }
        public byte[] Extensions { get; private set; }
        public bool UserPresent { get { return ((Flags & (1 << 0)) != 0); } }
        //public bool Reserved1 { get { return ((Flags & (1 << 1)) != 0); } }
        public bool UserVerified { get { return ((Flags & (1 << 2)) != 0); } }
        //public bool Reserved2 { get { return ((Flags & (1 << 3)) != 0); } }
        //public bool Reserved3 { get { return ((Flags & (1 << 4)) != 0); } }
        //public bool Reserved4 { get { return ((Flags & (1 << 5)) != 0); } }
        public bool AttestedCredentialDataPresent { get { return ((Flags & (1 << 6)) != 0); } }
        public bool ExtensionsPresent { get { return ((Flags & (1 << 7)) != 0); } }
    }
    // https://w3c.github.io/webauthn/#attested-credential-data
    public class AttestedCredentialData
    {
        public AttestedCredentialData(byte[] attData, ref int offset)
        {
            Aaguid = AuthDataHelper.GetSizedByteArray(attData, ref offset, 16);
            CredentialID = AuthDataHelper.GetSizedByteArray(attData, ref offset);
            // Determining attested credential data's length, which is variable, involves determining credentialPublicKey’s beginning location given the preceding credentialId’s length, and then determining the credentialPublicKey’s length
            var ms = new System.IO.MemoryStream(attData, offset, attData.Length - offset);
            // PeterO.Cbor.CBORObject.Read: This method will read from the stream until the end of the CBOR object is reached or an error occurs, whichever happens first.
            PeterO.Cbor.CBORObject tmp = null;
            try
            {
                tmp = PeterO.Cbor.CBORObject.Read(ms);
            }
            catch (Exception ex)
            {
                throw new Fido2VerificationException("Failed to read credential public key from attested credential data");
            }
            var aCDLen = tmp.EncodeToBytes().Length;
            
            CredentialPublicKey = AuthDataHelper.GetSizedByteArray(attData, ref offset, (UInt16)(aCDLen));
            if (null == Aaguid || null == CredentialID || null == CredentialPublicKey) throw new Fido2VerificationException("Attested credential data is invalid");
        }
        public byte[] Aaguid { get; private set; }
        public byte[] CredentialID { get; private set; }
        public byte[] CredentialPublicKey { get; private set; }
    }
}
