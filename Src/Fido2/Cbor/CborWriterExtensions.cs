using System;
using System.Formats.Cbor;

namespace Fido2NetLib.Cbor
{
    internal static class CborWriterExtensions
    {
        public static void WriteObject(this CborWriter writer, CborObject @object)
        {
            if (@object is CborTextString text)
            {
                writer.WriteTextString(text.Value);
            }
            else if (@object is CborByteString data)
            {
                writer.WriteByteString(data.Value);
            }
            else if (@object is CborInteger number)
            {
                writer.WriteInt64(number.Value);
            }
            else if (@object is CborMap map)
            {
                writer.WriteMap(map);
            }
            else if (@object is CborArray array)
            {
                writer.WriteArray(array);
            }
            else
            {
                throw new Exception("Unknown object: " + @object.Type.ToString());
            }
        }

        public static void WriteArray(this CborWriter writer, CborArray array)
        {
            writer.WriteStartArray(array.Length);

            foreach (var item in array.Values)
            {
                WriteObject(writer, item);
            }

            writer.WriteEndArray();
        }

        public static void WriteMap(this CborWriter writer, CborMap map)
        {
            writer.WriteStartMap(map.Count);

            foreach (var item in map)
            {
                WriteObject(writer, item.Key);
                WriteObject(writer, item.Value);
            }

            writer.WriteEndMap();
        }
    }
}
