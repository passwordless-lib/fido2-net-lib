using System;
using System.Buffers.Binary;

namespace Fido2NetLib;

internal ref struct MemoryReader
{
    public int _position;
    public readonly ReadOnlySpan<byte> _buffer;

    public MemoryReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    public int Position => _position;

    public void Advance(int count)
    {
        _position += count;
    }

    public uint ReadUInt32BigEndian()
    {
        var result = BinaryPrimitives.ReadUInt32BigEndian(_buffer.Slice(_position, 4));

        _position += 4;

        return result;
    }

    public byte[] ReadBytes(int count)
    {
        byte[] result = _buffer.Slice(_position, count).ToArray();

        _position += count;

        return result;
    }

    public byte ReadByte()
    {
        byte result = _buffer.Slice(_position)[0];

        _position += 1;

        return result;
    }

    public int RemainingBytes => _buffer.Length - _position;
}
