using System;
using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Serialization;

public sealed class AttestationTypeConverter : JsonConverter<AttestationType>
{
    public override AttestationType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return AttestationType.Get(reader.GetString()!);
    }

    public override void Write(Utf8JsonWriter writer, AttestationType value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Value);
    }
}
