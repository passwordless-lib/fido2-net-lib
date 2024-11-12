#nullable enable

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
    public static bool EnableRelaxedDecoding { get; set; }

    public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        byte[]? rentedBuffer = null;

        scoped ReadOnlySpan<byte> source;

        if (!reader.HasValueSequence && !reader.ValueIsEscaped)
        {
            source = reader.ValueSpan;
        }
        else
        {
            int valueLength = reader.HasValueSequence ? checked((int)reader.ValueSequence.Length) : reader.ValueSpan.Length;

            Span<byte> buffer = valueLength <= 32 ? stackalloc byte[32] : (rentedBuffer = ArrayPool<byte>.Shared.Rent(valueLength));
            int bytesRead = reader.CopyString(buffer);
            source = buffer[..bytesRead];
        }

        try
        {
            return Base64Url.DecodeFromUtf8(source);
        }
        catch
        {
            if (Base64.IsValid(source))
            {
                if (EnableRelaxedDecoding)
                {
                    return Base64Url.DecodeFromUtf8(source);                    
                }
                else
                {
                    throw new JsonException("Expected data to be in Base64Url format, but received Base64 encoding instead.");
                }
            }
            else
            {
                throw new JsonException("Invalid Base64Url data");
            }
        }
        finally
        {
            if (rentedBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(rentedBuffer);
            }
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
