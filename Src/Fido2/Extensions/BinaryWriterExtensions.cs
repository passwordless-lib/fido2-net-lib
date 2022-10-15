using System;
using System.Buffers.Binary;
using System.IO;

namespace Fido2NetLib;

internal static class BinaryWriterExtensions
{
    public static void WriteUInt16BigEndian(this BinaryWriter writer, ushort value)
    {
        Span<byte> buffer = stackalloc byte[2];

        BinaryPrimitives.WriteUInt16BigEndian(buffer, value);

        writer.Write(buffer);
    }

    public static void WriteUInt32BigEndian(this BinaryWriter writer, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];

        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);

        writer.Write(buffer);
    }
}
