using System;
using System.IO;
using System.Linq;

namespace fido2NetLib
{
    /// <summary>
    /// Helper functions that implements https://w3c.github.io/webauthn/#authenticator-data
    /// </summary>
    public static class AuthDataHelper
    {
        /// <summary>
        /// Parses the encoded Signature data to a byte array (DER  / ASN.1 decode)
        /// todo: Improve this notes
        /// </summary>
        /// <param name="sigData"></param>
        /// <returns></returns>
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
            string hex = BitConverter.ToString(credentialPublicKey);

            return (aaguid, credIdLen, credId, credentialPublicKey);

            // convert to jwk
            // convert to pem


        }
    }
}
