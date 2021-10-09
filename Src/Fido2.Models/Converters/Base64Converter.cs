using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib
{
    /// <summary>
    /// Custom Converter for encoding/encoding byte[] using Base64Url instead of default Base64.
    /// </summary>
    public sealed class Base64UrlConverter : JsonConverter<byte[]>
    {
        public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (!reader.HasValueSequence)
            {
                return Base64Url.DecodeUtf8(reader.ValueSpan);
            }
            else
            {
                return Base64Url.Decode(reader.GetString());
            }
        }

        public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(Base64Url.Encode(value));
        }
    }
}
