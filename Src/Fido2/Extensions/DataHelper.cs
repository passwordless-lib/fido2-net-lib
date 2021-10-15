using System;

namespace Fido2NetLib
{
    internal static class DataHelper
    {
        public static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            var result = new byte[a.Length + b.Length];

            a.CopyTo(result);
            b.CopyTo(result.AsSpan(a.Length));

            return result;
        }

        public static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
        {
            var result = new byte[a.Length + b.Length + c.Length];

            a.CopyTo(result);
            b.CopyTo(result.AsSpan(a.Length));
            c.CopyTo(result.AsSpan(a.Length + b.Length));

            return result;
        }
    }
}
