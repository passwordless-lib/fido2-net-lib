using System;
using System.Collections.Generic;
using System.Formats.Cbor;

namespace Fido2NetLib.Cbor;

public abstract class CborObject
{
    /// <summary>
    /// The deepest nesting of arrays and maps <see cref="Decode(ReadOnlyMemory{byte})"/> accepts, counting the
    /// outermost container as depth 1.
    /// </summary>
    /// <remarks>
    /// Decoding recurses once per level, and the input is attacker-controlled: without a bound, a request of a
    /// few hundred kilobytes of nested one-element arrays overflows the stack, which .NET cannot catch and which
    /// terminates the process. Nothing WebAuthn or CTAP defines comes close to this -- a compound attestation
    /// object, the deepest, nests five levels (object, attStmt array, sub-statement, attStmt, x5c).
    /// </remarks>
    internal const int MaxNestingDepth = 16;

    public abstract CborType Type { get; }

    public static CborObject Decode(ReadOnlyMemory<byte> data)
    {
        var reader = new CborReader(data);

        return Read(reader, depth: 0);
    }

    public static CborObject Decode(ReadOnlyMemory<byte> data, out int bytesRead)
    {
        var reader = new CborReader(data);

        var result = Read(reader, depth: 0);

        bytesRead = data.Length - reader.BytesRemaining;

        return result;
    }

    public virtual CborObject this[int index] => null!;

    public virtual CborObject? this[string name] => null;

    public static explicit operator string(CborObject obj)
    {
        return ((CborTextString)obj).Value;
    }

    public static explicit operator byte[](CborObject obj)
    {
        return ((CborByteString)obj).Value;
    }

    public static explicit operator int(CborObject obj)
    {
        return (int)((CborInteger)obj).Value;
    }

    public static explicit operator long(CborObject obj)
    {
        return ((CborInteger)obj).Value;
    }

    public static explicit operator bool(CborObject obj)
    {
        return ((CborBoolean)obj).Value;
    }

    private static CborObject Read(CborReader reader, int depth)
    {
        CborReaderState s = reader.PeekState();

        return s switch
        {
            CborReaderState.StartMap => ReadMap(reader, EnterContainer(depth)),
            CborReaderState.StartArray => ReadArray(reader, EnterContainer(depth)),
            CborReaderState.TextString => new CborTextString(reader.ReadTextString()),
            CborReaderState.Boolean => (CborBoolean)reader.ReadBoolean(),
            CborReaderState.ByteString => new CborByteString(reader.ReadByteString()),
            CborReaderState.UnsignedInteger => new CborInteger(reader.ReadInt64()),
            CborReaderState.NegativeInteger => new CborInteger(reader.ReadInt64()),
            CborReaderState.Null => ReadNull(reader),
            _ => throw new Exception($"Unhandled state. Was {s}")
        };
    }

    private static CborNull ReadNull(CborReader reader)
    {
        reader.ReadNull();

        return CborNull.Instance;
    }

    private static int EnterContainer(int depth)
    {
        if (depth >= MaxNestingDepth)
            throw new CborContentException($"CBOR arrays and maps are nested more than {MaxNestingDepth} levels deep");

        return depth + 1;
    }

    private static CborArray ReadArray(CborReader reader, int depth)
    {
        int? count = reader.ReadStartArray();

        var items = count != null
            ? new List<CborObject>(count.Value)
            : [];

        while (!(reader.PeekState() is CborReaderState.EndArray or CborReaderState.Finished))
        {
            items.Add(Read(reader, depth));
        }

        reader.ReadEndArray();

        return new CborArray(items);
    }

    private static CborMap ReadMap(CborReader reader, int depth)
    {
        int? count = reader.ReadStartMap();

        var map = count.HasValue ? new CborMap(count.Value) : new CborMap();

        while (!(reader.PeekState() is CborReaderState.EndMap or CborReaderState.Finished))
        {
            CborObject k = Read(reader, depth);
            CborObject v = Read(reader, depth);

            map.Add(k, v);
        }

        reader.ReadEndMap();

        return map;
    }

    public byte[] Encode()
    {
        var writer = new CborWriter();

        writer.WriteObject(this);

        return writer.Encode();
    }
}
