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
            {
                var text = reader.GetString();

                // Map to an enum value using the EnumMemberAttribute
                if (EnumNameMapper<T>.TryGetValue(text, out var valueByMemberName))
                    return valueByMemberName;

                // Map to an enum value directly by name
                if (Enum.TryParse<T>(text, true, out var valueByName))
                    return valueByName;

                throw new JsonException($"Invalid enum value = \"{text}\"");
            }

            case JsonTokenType.Number:
            {
                if (!reader.TryGetInt32(out var number))
                    throw new JsonException($"Invalid enum value = {reader.GetString()}");

                var casted = (T)(object)number; // ints can always be cast to enum, even when the value is not defined
                if (Enum.IsDefined(casted))
                    return casted;

                throw new JsonException($"Invalid enum value = {number}");
            }

            default:
            {
                throw new JsonException($"Invalid enum value ({reader.TokenType})");
            }
        }
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(EnumNameMapper<T>.GetName(value));
    }
}
