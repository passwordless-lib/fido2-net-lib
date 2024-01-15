using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

public sealed class FidoEnumConverter<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] T> : JsonConverter<T>
    where T : struct, Enum
{
    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.String:
                string text = reader.GetString();
                if (EnumNameMapper<T>.TryGetValue(text, out T value))
                    return value;
                else
                    throw new JsonException($"Invalid enum value = \"{text}\"");

            case JsonTokenType.Number:
                if (!reader.TryGetInt32(out var number))
                    throw new JsonException($"Invalid enum value = {reader.GetString()}");
                var casted = (T)(object)number; // ints can always be casted to enum, even when the value is not defined
                if (Enum.IsDefined(casted))
                    return casted;
                else
                    throw new JsonException($"Invalid enum value = {number}");

            default:
                throw new JsonException($"Invalid enum value ({reader.TokenType})");
        }
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(EnumNameMapper<T>.GetName(value));
    }
}
