using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Fido2NetLib;

internal static class IBufferWriterExtensions
{
    public static void WriteUInt16BigEndian(this IBufferWriter<byte> writer, ushort value)
    {
        var buffer = writer.GetSpan(2);

        BinaryPrimitives.WriteUInt16BigEndian(buffer, value);

        writer.Advance(2);
    }

    public static void WriteUInt32BigEndian(this IBufferWriter<byte> writer, uint value)
    {
        var buffer = writer.GetSpan(4);

        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);

        writer.Advance(4);
    }

    public static void WriteGuidBigEndian(this IBufferWriter<byte> writer, Guid value)
    {
        var buffer = writer.GetSpan(16);

        _ = value.TryWriteBytes(buffer);

        if (BitConverter.IsLittleEndian)
        {
            SwapBytes(buffer, 0, 3);
            SwapBytes(buffer, 1, 2);
            SwapBytes(buffer, 4, 5);
            SwapBytes(buffer, 6, 7);
        }

        writer.Advance(16);
    }

    private static void SwapBytes(Span<byte> bytes, int index1, int index2)
    {
        var temp = bytes[index1];
        bytes[index1] = bytes[index2];
        bytes[index2] = temp;
    }
}
