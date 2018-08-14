using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace fido2NetLib
{
    /// <summary>
    /// Helper functions that implements https://w3c.github.io/webauthn/#authenticator-data
    /// </summary>
    public static class AuthDataHelper
    {
        public static ReadOnlySpan<byte> AaguidFromAttnCertExts(X509ExtensionCollection exts)
        {
            var aaguid = new byte[16];
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.1.1.4")) // id-fido-gen-ce-aaguid
                {
                    var ms = new System.IO.MemoryStream(ext.RawData.ToArray());
                    // OCTET STRING
                    if (0x4 != ms.ReadByte()) throw new Fido2VerificationException();
                    // AAGUID
                    if (0x10 != ms.ReadByte()) throw new Fido2VerificationException();
                    ms.Read(aaguid, 0, 0x10);
                    //The extension MUST NOT be marked as critical
                    if (true == ext.Critical) throw new Fido2VerificationException();
                }
            }
            return aaguid;
        }
        public static ReadOnlySpan<byte> SANFromAttnCertExts(X509ExtensionCollection exts)
        {
            var SAN = new byte[0];
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.17")) // subject alternative name
                {
                    return ext.RawData.ToArray();
                }
            }
            return SAN;
        }
        public static ReadOnlySpan<byte> EKUFromAttnCertExts(X509ExtensionCollection exts)
        {
            var EKU = new byte[0];
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.37")) // subject alternative name
                {
                    return ext.RawData.ToArray();
                }
            }
            return EKU;
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

        public static int U2FTransportsFromAttnCert(X509ExtensionCollection exts)
        {
            var u2ftransports = 0;
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.2.1.1"))
                {
                    var ms = new System.IO.MemoryStream(ext.RawData.ToArray());
                    // BIT STRING
                    if (0x3 != ms.ReadByte()) throw new Fido2VerificationException();
                    if (0x2 != ms.ReadByte()) throw new Fido2VerificationException();
                    var unused = ms.ReadByte(); // unused byte
                    // https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-authenticator-transports-extension-v1.1-id-20160915.html#fido-u2f-certificate-transports-extension
                    u2ftransports = ms.ReadByte(); // do something with this?
                }
            }
            return u2ftransports;
        }

        public static bool IsValidPackedAttnCertSubject(string attnCertSubj)
        {
            var dictSubject = attnCertSubj.Split(", ").Select(part => part.Split('=')).ToDictionary(split => split[0], split => split[1]);
            return (0 != dictSubject["C"].Length ||
                0 != dictSubject["O"].Length ||
                0 != dictSubject["OU"].Length ||
                0 != dictSubject["CN"].Length ||
                "Authenticator Attestation" == dictSubject["OU"].ToString());
        }

        public static (Memory<byte> publicKeyU2F, int COSE_alg) U2FKeyFromCOSEKey(PeterO.Cbor.CBORObject COSEKey)
        {
            var COSE_kty = COSEKey[PeterO.Cbor.CBORObject.FromObject(1)]; // 2 == EC2
            var COSE_alg = COSEKey[PeterO.Cbor.CBORObject.FromObject(3)]; // -7 == ES256 signature 
            var COSE_crv = COSEKey[PeterO.Cbor.CBORObject.FromObject(-1)]; // 1 == P-256 curve 
            var x = COSEKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString();
            var y = COSEKey[PeterO.Cbor.CBORObject.FromObject(-3)].GetByteString();
            var publicKeyU2F = new byte[1] { 0x4 }; // uncompressed
            publicKeyU2F = publicKeyU2F.Concat(x).Concat(y).ToArray();
            return (publicKeyU2F, COSE_alg.AsInt32());
        }

        public static ReadOnlySpan<byte> ParseSigData(ReadOnlySpan<byte> sigData)
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

            var ms = new System.IO.MemoryStream(sigData.ToArray());
            if (0x30 != ms.ReadByte()) throw new Fido2VerificationException(); // DER SEQUENCE
            var dataLen = ms.ReadByte(); // length of r + s
            if (0x2 != ms.ReadByte()) throw new Fido2VerificationException(); // DER INTEGER
            var rLen = ms.ReadByte(); // length of r
            if (0 != (rLen % 8)) // must be on 8 byte boundary
            {
                if (0 == ms.ReadByte()) rLen--; // strip leading 0x00
                else throw new Fido2VerificationException();
            }
            var r = new byte[rLen]; // r
            ms.Read(r, 0, r.Length);

            if (0x2 != ms.ReadByte()) throw new Fido2VerificationException(); // DER INTEGER
            var sLen = ms.ReadByte(); // length of s
            if (0 != (sLen % 8)) // must be on 8 byte boundary
            {
                if (0 == ms.ReadByte()) sLen--; // strip leading 0x00
                else throw new Fido2VerificationException();
            }
            var s = new byte[sLen]; // s
            ms.Read(s, 0, s.Length);

            var sig = new byte[r.Length + s.Length];
            r.CopyTo(sig, 0);
            s.CopyTo(sig, r.Length);
            return sig;
        }

        public static ReadOnlySpan<byte> GetRpIdHash(ReadOnlySpan<byte> authData)
        {
            // todo: Switch to spans
            return authData.Slice(0, 32);
        }

        public static bool IsUserPresent(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x01) != 0;
        }

        public static bool HasExtensions(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x80) != 0;
        }

        public static bool HasAttested(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x40) != 0;
        }

        public static bool IsUserVerified(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x04) != 0;
        }

        public static uint GetSignCount(ReadOnlySpan<byte> ad)
        {
            var bytes = ad.Slice(33, 4);
            var reversebytes = bytes.ToArray().Reverse().ToArray();
            return BitConverter.ToUInt32(reversebytes);
            //return BitConverter.ToUInt32(ad.Slice(33, 4),);
            //using (var ms = new MemoryStream(ad.ToArray()))
            //using (var br = new BinaryReader(ms))
            //{
            //    var pos = br.BaseStream.Seek(33, SeekOrigin.Current);
            //    var x = br.ReadUInt32();
            //    // https://w3c.github.io/webauthn/#attestedcredentialdata
            //    
            //    return x;
            //}
        }

        public static (Memory<byte> aaguid, int credIdLen, Memory<byte> credId, Memory<byte> credentialPublicKey) GetAttestionData(Memory<byte> ad)
        {
            string hex2 = BitConverter.ToString(ad.ToArray());

            int offset = 37; // https://w3c.github.io/webauthn/#attestedcredentialdata
            var aaguid = ad.Slice(offset, 16);
            var guid = new Guid(aaguid.ToArray());
            offset += 16;
            // todo: Do we need to account for little endian?
            ushort credIdLen;
            if (true == BitConverter.IsLittleEndian)
            {
                credIdLen = BitConverter.ToUInt16(ad.Slice(offset, 2).ToArray().Reverse().ToArray());
            }
            else
            {
                credIdLen = BitConverter.ToUInt16(ad.Slice(offset, 2).Span);
            }
            offset += 2;

            var credId = ad.Slice(offset, credIdLen);

            offset += credIdLen;

            var hasExtensions = AuthDataHelper.HasExtensions(ad.Span);

            // Not sure this is working as expected...
            var credentialPublicKey = ad.Slice(offset, (ad.Length - offset)).ToArray();

            // for debugging...
            //string hex = BitConverter.ToString(credentialPublicKey);

            return (aaguid, credIdLen, credId, credentialPublicKey);

            // convert to jwk
            // convert to pem


        }
        public static byte[] GetSizedByteArray(Memory<byte> ab, ref int offset)
        {
            var len = BitConverter.ToUInt16(ab.Slice(offset, 2).ToArray().Reverse().ToArray());
            offset += 2;
            var result = ab.Slice(offset, len).ToArray();
            offset += len;
            return result;
        }

        public static (int size, byte[] name) NameFromTPM2BName(Memory<byte> ab)
        {
            // This buffer holds a Name for any entity type. 
            // The type of Name in the structure is determined by context and the size parameter. 
            var size = BitConverter.ToUInt16(ab.Slice(0, 2).ToArray().Reverse().ToArray());
            // If size is four, then the Name is a handle. 
            if (4 == size) throw new Fido2VerificationException("Unexpected handle in TPM2B_NAME");
            // If size is zero, then no Name is present. 
            if (0 == size) throw new Fido2VerificationException("Unexpected no name found in TPM2B_NAME");
            // Otherwise, the size shall be the size of a TPM_ALG_ID plus the size of the digest produced by the indicated hash algorithm.
            TpmAlg tmpalg = (TpmAlg)Enum.Parse(typeof(TpmAlg), size.ToString());
            // where to get size of digest for given alg?  assume 32 bytes for now
            var name = ab.Slice(2, 32).ToArray();
            return (size, name);
        }
        // TPM_ALG_ID 
        public enum TpmAlg : UInt16
        {
            TPM_ALG_ERROR, // 0
            TPM_ALG_RSA, // 1
            TPM_ALG_SHA1 = 4, // 4
            TPM_ALG_HMAC, // 5
            TPM_ALG_AES, // 6
            TPM_ALG_MGF1, // 7
            TPM_ALG_KEYEDHASH, // 8
            TPM_ALG_XOR = 0xA, // A
            TPM_ALG_SHA256, // B
            TPM_ALG_SHA384, // C
            TPM_ALG_SHA512, // D
            TPM_ALG_NULL = 0x10, // 10
            TPM_ALG_SM3_256 = 0x12, // 12
            TPM_ALG_SM4, // 13
            TPM_ALG_RSASSA, // 14
            TPM_ALG_RSAES, // 15
            TPM_ALG_RSAPSS, // 16
            TPM_ALG_OAEP, // 17
            TPM_ALG_ECDSA, // 18
            TPM_ALG_ECDH, // 19
            TPM_ALG_ECDAA, // 1A
            TPM_ALG_SM2, // 1B
            TPM_ALG_ECSCHNORR, // 1C
            TPM_ALG_ECMQV, // 1D
            TPM_ALG_KDF1_SP800_56A = 0x20, 
            TPM_ALG_KDF2, // 21
            TPM_ALG_KDF1_SP800_108, // 22
            TPM_ALG_ECC, // 23
            TPM_ALG_SYMCIPHER = 0x25,
            TPM_ALG_CAMELLIA, // 26
            TPM_ALG_CTR = 0x40,
            TPM_ALG_OFB, // 41
            TPM_ALG_CBC, // 42 
            TPM_ALG_CFB, // 43
            TPM_ALG_ECB // 44
        };
        public static (Memory<byte> extraData, Memory<byte> attested) ParseCertInfo(Memory<byte> certInfo)
        {
            var offset = 0;
            var magic = certInfo.Slice(offset, 4);
            if (0xff544347 != BitConverter.ToUInt32(magic.ToArray().Reverse().ToArray())) throw new Fido2VerificationException("Bad magic number " + magic.ToString());
            offset += 4;
            var type = certInfo.Slice(offset, 2);
            if (0x8017 != BitConverter.ToUInt16(type.ToArray().Reverse().ToArray())) throw new Fido2VerificationException("Bad structure tag " + type.ToString());
            offset += 2;
            var qualifiedSigner = GetSizedByteArray(certInfo, ref offset);
            var extraData = GetSizedByteArray(certInfo, ref offset);
            var clock = certInfo.Slice(offset, 8);
            offset += 8;
            var resetCount = BitConverter.ToInt32(certInfo.Slice(offset, 4).ToArray().Reverse().ToArray());
            offset += 4;
            var restartCount = BitConverter.ToInt32(certInfo.Slice(offset, 4).ToArray().Reverse().ToArray());
            offset += 4;
            var safe = certInfo.Slice(offset, 1);
            offset += 1;
            var firmwareVersion = certInfo.Slice(offset, 8);
            offset += 8;
            var attestedNameBuffer = GetSizedByteArray(certInfo, ref offset);
            var tmp = NameFromTPM2BName(attestedNameBuffer);
            var alg = tmp.size; // TPM_ALG_ID
            var attestedName = tmp.name;
            var attestedQualifiedNameBuffer = GetSizedByteArray(certInfo, ref offset);
            if (certInfo.Length != offset) throw new Fido2VerificationException("Leftover bits decoding certInfo");
            return (extraData, attestedName);
        }
        public static (Memory<byte> alg, int exponent, Memory<byte> unique) ParsePubArea(Memory<byte> pubArea)
        {
            var offset = 0;
            var type = pubArea.Slice(offset, 2);
            offset += 2;
            var alg = pubArea.Slice(offset, 2);
            TpmAlg tmpalg = (TpmAlg)Enum.Parse(typeof(TpmAlg), BitConverter.ToUInt16(alg.ToArray().Reverse().ToArray()).ToString());
            offset += 2;
            var atts = pubArea.Slice(offset, 4);
            offset += 4;
            var policy = GetSizedByteArray(pubArea, ref offset);
            var symmetric = pubArea.Slice(offset, 2);
            offset += 2;
            var scheme = pubArea.Slice(offset, 2);
            offset += 2;
            //if (0x0001 == BitConverter.ToInt16(type.ToArray().Reverse().ToArray()))
            //{
            var keyBits = pubArea.Slice(offset, 2);
            offset += 2;
            var tmp = pubArea.Slice(offset, 4);
            offset += 4;
            var exponent = BitConverter.ToInt32(tmp.ToArray());
            if (0x0 == exponent) exponent = 65537;
            //}
            //else if (0x0023 == BitConverter.ToInt16(type.ToArray().Reverse().ToArray()))
            //{
            //    var curveID = pubArea.Slice(offset, 2);
            //    offset += 2;
            //    var kdf = pubArea.Slice(offset, 2);
            //    offset += 2;
            //}
            var unique = GetSizedByteArray(pubArea, ref offset);
            if (pubArea.Length != offset) throw new Fido2VerificationException("Leftover bits decoding pubArea");
            return (alg, exponent, unique);
        }
    }
}
