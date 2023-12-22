using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

public sealed class FidoEnumConverter<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] T> : JsonConverter<T>
    where T : struct, Enum
{
    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string text = reader.GetString();

        if (EnumNameMapper<T>.TryGetValue(reader.GetString(), out T value))
        {
            return value;
        }
        else
        {
            throw new JsonException($"Invalid enum value = {text}");
        }
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(EnumNameMapper<T>.GetName(value));
    }
}
