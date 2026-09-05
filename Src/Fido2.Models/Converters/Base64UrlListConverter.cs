using System.Buffers.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Converts a JSON array of base64url strings to and from a list of byte arrays, for spec dictionaries typed as
/// <c>sequence&lt;Base64URLString&gt;</c>.
/// </summary>
public sealed class Base64UrlListConverter : JsonConverter<IReadOnlyList<byte[]>>
{
    public override IReadOnlyList<byte[]>? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is JsonTokenType.Null)
            return null;

        if (reader.TokenType is not JsonTokenType.StartArray)
            throw new JsonException($"Expected an array of base64url strings, got {reader.TokenType}");

        List<byte[]> items = [];

        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.EndArray:
                    return items;

                case JsonTokenType.String:
                    items.Add(Base64Url.DecodeFromChars(reader.GetString()));
                    break;

                default:
                    throw new JsonException($"Expected a base64url string, got {reader.TokenType}");
            }
        }

        throw new JsonException("Unexpected end of JSON while reading a base64url array");
    }

    public override void Write(Utf8JsonWriter writer, IReadOnlyList<byte[]> value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();

        foreach (var item in value)
        {
            writer.WriteStringValue(Base64Url.EncodeToChars(item));
        }

        writer.WriteEndArray();
    }
}
