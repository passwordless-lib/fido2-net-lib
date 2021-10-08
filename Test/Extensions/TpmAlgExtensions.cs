using System.Buffers.Binary;

using Fido2NetLib;

namespace Test
{
    internal static class TpmAlgExtensions
    {
        public static byte[] ToUInt16BigEndianBytes(this TpmAlg alg)
        {
            var bytes = new byte[2];

            BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort)alg);

            return bytes;
        }
    }
}
