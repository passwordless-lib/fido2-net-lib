using System;
using System.Linq;
using PeterO.Cbor;

namespace Fido2NetLib
{
    /// <summary>
    /// Helper functions that implements https://w3c.github.io/webauthn/#authenticator-data
    /// </summary>
    public static class AuthDataHelper
    {
        public static byte[] GetSizedByteArray(Memory<byte> ab, ref int offset, ushort len = 0)
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
    }
}
