using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Fido2NetLib;

internal static class IBufferWriterExtensions
{
    public static void WriteUInt16BigEndian(this IBufferWriter<byte> writer, ushort value)
    {
        Span<byte> buffer = stackalloc byte[2];

        BinaryPrimitives.WriteUInt16BigEndian(buffer, value);

        writer.Write(buffer);
    }

    public static void WriteUInt32BigEndian(this IBufferWriter<byte> writer, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];

        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);

        writer.Write(buffer);
    }
}
