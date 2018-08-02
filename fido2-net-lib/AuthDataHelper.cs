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
        public static (Memory<byte> x, Memory<byte> y) CoseKeyToU2F(Memory<byte> CoseKey)
        {
            // Not pretty, but seems to work
            var ms = new System.IO.MemoryStream(CoseKey.ToArray());
            if (0xA5 != ms.ReadByte()) throw new Fido2VerificationException(); // header
            if (0x1 != ms.ReadByte()) throw new Fido2VerificationException();  // kty header
            var kty = ms.ReadByte(); // 2 is "EC"?
            if (0x3 != ms.ReadByte()) throw new Fido2VerificationException();  // alg header
            var alg = ms.ReadByte(); // 38 ?
            if (0x20 != ms.ReadByte()) throw new Fido2VerificationException();  // crv header
            var crv = ms.ReadByte(); // 1 ?
            if (0x21 != ms.ReadByte()) throw new Fido2VerificationException();  // x header
            if (0x58 != ms.ReadByte()) throw new Fido2VerificationException();  // ?
            if (0x20 != ms.ReadByte()) throw new Fido2VerificationException();  // x.Length must be 32
            var x = new byte[0x20];
            ms.Read(x, 0, 0x20);

            if (0x22 != ms.ReadByte()) throw new Fido2VerificationException();  // y header
            if (0x58 != ms.ReadByte()) throw new Fido2VerificationException();  // ?
            if (0x20 != ms.ReadByte()) throw new Fido2VerificationException();  // y.Length must be 32
            var y = new byte[0x20];
            ms.Read(y, 0, 0x20);

            return (x, y);
        }
        public static ReadOnlySpan<byte> ParseSigData(ReadOnlySpan<byte> sigData)
        {
            // Not pretty, but seems to work
            var ms = new System.IO.MemoryStream(sigData.ToArray());
            if (0x30 != ms.ReadByte()) throw new Fido2VerificationException(); // header
            var dataLen = ms.ReadByte(); // all bytes
            if (0x2 != ms.ReadByte()) throw new Fido2VerificationException();
            var rLen = ms.ReadByte(); // length of r
            if (0 != (rLen % 8)) // must be on 8 byte boundary
            {
                if (0 == ms.ReadByte()) rLen--; // throw away signing byte
                else throw new Fido2VerificationException();
            }
            var r = new byte[rLen]; // r
            ms.Read(r, 0, r.Length);

            if (0x2 != ms.ReadByte()) throw new Fido2VerificationException();
            var sLen = ms.ReadByte(); // length of s
            if (0 != (sLen % 8)) // must be on 8 byte boundary
            {
                if (0 == ms.ReadByte()) sLen--; // throw away signing byte
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
