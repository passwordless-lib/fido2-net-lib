using System.Buffers;
using System.Buffers.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Custom Converter for encoding/encoding byte[] using Base64Url instead of default Base64.
/// </summary>
public sealed class Base64UrlConverter : JsonConverter<byte[]>
{
    public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (!reader.HasValueSequence)
        {
            return Base64Url.DecodeFromUtf8(reader.ValueSpan);
        }
        else
        {
            return Base64Url.DecodeFromChars(reader.GetString());
        }
    }

    public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
    {
        var rentedBuffer = ArrayPool<byte>.Shared.Rent(Base64Url.GetEncodedLength(value.Length));

        try
        {
            Base64Url.EncodeToUtf8(value, rentedBuffer, out _, out int written);

            writer.WriteStringValue(rentedBuffer.AsSpan(0..written));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentedBuffer);
        }
    }
}
