using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Reads an array of CTAP command/subCommand identifiers, which CBOR encodes as an unsigned integer up to
/// <see cref="ulong.MaxValue"/>.
/// </summary>
/// <remarks>
/// Some tooling that produces the JSON <c>authenticatorGetInfo</c> structure round-trips these values through an
/// IEEE-754 double (as JavaScript's <c>Number</c> type does), which can render a value near <see cref="ulong.MaxValue"/>
/// as a JSON integer literal that is technically out of range for <see cref="ulong"/> -- e.g. 18446744073709552000
/// rather than 18446744073709551615. <see cref="Utf8JsonReader.GetUInt64"/> rejects such a literal outright, so it
/// is instead read as a double and clamped back into range rather than aborting deserialization of the whole
/// metadata statement over an already lossy value.
/// </remarks>
public sealed class CommandIdentifierArrayConverter : JsonConverter<ulong[]>
{
    public override ulong[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is JsonTokenType.Null)
            return null;

        if (reader.TokenType is not JsonTokenType.StartArray)
            throw new JsonException($"Expected an array of command identifiers, got {reader.TokenType}");

        List<ulong> commands = [];

        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.EndArray:
                    return [.. commands];

                case JsonTokenType.Number:
                    commands.Add(reader.TryGetUInt64(out var value) ? value : ClampToUInt64(reader.GetDouble()));
                    break;

                default:
                    throw new JsonException($"Expected a command identifier, got {reader.TokenType}");
            }
        }

        throw new JsonException("Unexpected end of JSON while reading command identifiers");
    }

    private static ulong ClampToUInt64(double value) => value >= ulong.MaxValue ? ulong.MaxValue : (ulong)value;

    public override void Write(Utf8JsonWriter writer, ulong[] value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();

        foreach (var command in value)
        {
            writer.WriteNumberValue(command);
        }

        writer.WriteEndArray();
    }
}
