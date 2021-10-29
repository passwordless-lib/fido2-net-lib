using System;
using System.Collections.Generic;
using System.Formats.Cbor;

namespace Fido2NetLib.Cbor
{
    public abstract class CborObject
    {
        public abstract CborType Type { get; }

        public static CborObject Parse(ReadOnlyMemory<byte> data)
        {
            var reader = new CborReader(data);

            return Read(reader);
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

        private static CborObject Read(CborReader reader)
        {
            CborReaderState s = reader.PeekState();

            return s switch
            {
                CborReaderState.StartMap        => ReadMap(reader),
                CborReaderState.StartArray      => ReadArray(reader),
                CborReaderState.TextString      => new CborTextString(reader.ReadTextString()),
                CborReaderState.ByteString      => new CborByteString(reader.ReadByteString()),
                CborReaderState.UnsignedInteger => new CborInteger(reader.ReadInt64()),
                CborReaderState.NegativeInteger => new CborInteger(reader.ReadInt64()),
                CborReaderState.Null            => ReadNull(reader),
                _                               => throw new Exception($"Unhandled state. Was {s}")
            };
        }

        private static CborNull ReadNull(CborReader reader)
        {
            reader.ReadNull();

            return CborNull.Instance;
        }

        private static CborArray ReadArray(CborReader reader)
        {
            var items = new List<CborObject>();

            reader.ReadStartArray();

            while (reader.PeekState() != CborReaderState.EndArray)
            {
                items.Add(Read(reader));
            }

            reader.ReadEndArray();

            return new CborArray(items);
        }

        private static CborMap ReadMap(CborReader reader)
        {
            int? count = reader.ReadStartMap();

            var map = count.HasValue ? new CborMap(count.Value) : new CborMap();

            while (!(reader.PeekState() is CborReaderState.EndMap or CborReaderState.Finished))
            {
                CborObject k = Read(reader);
                CborObject v = Read(reader);

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
}
