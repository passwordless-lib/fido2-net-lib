using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Reads an array of <see cref="AuthenticatorTransport"/> values, silently discarding entries the library does
/// not recognize.
/// </summary>
/// <remarks>
/// <para>
/// The <c>transports</c> member of an attestation response is whatever the client returned from
/// <c>getTransports()</c>. WebAuthn Level 3 states that these values SHOULD be members of
/// <c>AuthenticatorTransport</c> "but Relying Parties SHOULD accept and store unknown values"
/// (<see href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-gettransports"/>), and clients do in
/// practice return values outside the enumeration. Failing to deserialize such a response would abort an otherwise
/// valid registration ceremony over an advisory hint, so unrecognized values are dropped instead.
/// </para>
/// <para>
/// Note that dropping is not the same as storing: a Relying Party that needs to round-trip transport values it does
/// not recognize has to retain the raw JSON itself.
/// </para>
/// </remarks>
public sealed class AuthenticatorTransportArrayConverter : JsonConverter<AuthenticatorTransport[]>
{
    public override AuthenticatorTransport[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is JsonTokenType.Null)
            return null;

        if (reader.TokenType is not JsonTokenType.StartArray)
            throw new JsonException($"Expected an array of transports, got {reader.TokenType}");

        List<AuthenticatorTransport> transports = [];

        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.EndArray:
                    return [.. transports];

                case JsonTokenType.String:
                    if (EnumNameMapper<AuthenticatorTransport>.TryGetValue(reader.GetString()!, out var transport))
                        transports.Add(transport);

                    // An unrecognized transport is not an error; see the remarks on this type.
                    break;

                default:
                    throw new JsonException($"Expected a transport string, got {reader.TokenType}");
            }
        }

        throw new JsonException("Unexpected end of JSON while reading transports");
    }

    public override void Write(Utf8JsonWriter writer, AuthenticatorTransport[] value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();

        foreach (var transport in value)
        {
            writer.WriteStringValue(EnumNameMapper<AuthenticatorTransport>.GetName(transport));
        }

        writer.WriteEndArray();
    }
}
