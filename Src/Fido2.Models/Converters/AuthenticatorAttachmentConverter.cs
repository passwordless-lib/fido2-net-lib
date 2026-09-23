using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Reads the <c>authenticatorAttachment</c> reported by the client, mapping any value the library does not
/// recognize to <see langword="null"/>.
/// </summary>
/// <remarks>
/// WebAuthn Level 3 says of this attribute that "Relying Parties SHOULD treat unknown values as if the value
/// were <c>null</c>" (<see href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment"/>),
/// so an attachment the library cannot name must not fail the ceremony. The value is advisory in any case: it is
/// not signed by the authenticator, so it must never carry security weight.
/// </remarks>
public sealed class AuthenticatorAttachmentConverter : JsonConverter<AuthenticatorAttachment?>
{
    public override AuthenticatorAttachment? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is JsonTokenType.Null)
            return null;

        if (reader.TokenType is not JsonTokenType.String)
            throw new JsonException($"Expected an authenticatorAttachment string, got {reader.TokenType}");

        return EnumNameMapper<AuthenticatorAttachment>.TryGetValue(reader.GetString()!, out var attachment)
            ? attachment
            : null;
    }

    public override void Write(Utf8JsonWriter writer, AuthenticatorAttachment? value, JsonSerializerOptions options)
    {
        if (value is null)
            writer.WriteNullValue();
        else
            writer.WriteStringValue(EnumNameMapper<AuthenticatorAttachment>.GetName(value.Value));
    }
}
