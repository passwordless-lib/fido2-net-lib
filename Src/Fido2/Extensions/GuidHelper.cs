using System;

namespace Fido2NetLib;

internal static class GuidHelper
{
    private static void SwapBytes(byte[] bytes, int index1, int index2)
    {
        byte temp = bytes[index1];
        bytes[index1] = bytes[index2];
        bytes[index2] = temp;
    }

    /// <summary>
    /// AAGUID is sent as big endian byte array, this converter is for little endian systems.
    /// </summary>
    public static Guid FromBigEndian(byte[] bytes)
    {
        if (!BitConverter.IsLittleEndian)
        {
            // we're already on a big-endian system, keep the bytes as is
            return new Guid(bytes);
        }

        // swap the bytes to little-endian

        SwapBytes(bytes, 0, 3);
        SwapBytes(bytes, 1, 2);
        SwapBytes(bytes, 4, 5);
        SwapBytes(bytes, 6, 7);

        return new Guid(bytes);
    }
}
