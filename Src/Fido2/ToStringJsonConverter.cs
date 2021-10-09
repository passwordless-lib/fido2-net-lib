#nullable disable

using System;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib
{
    public class ToStringJsonConverter<T> : JsonConverter<T>
        where T: notnull
    {
        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string text = reader.GetString();

            var p = typeof(T).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { typeof(string) }, null);
            if (p != null)
            {
                return (T)p.Invoke(new object[] { text });
            }

            throw new JsonException("Invalid T");
        }

        public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.ToString());
        }
    }
}
