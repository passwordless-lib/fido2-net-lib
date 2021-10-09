using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib
{
    public sealed class FidoEnumConverter<T> : JsonConverter<T>
        where T: struct, Enum
    {
        private static readonly Dictionary<T, string> valueToNames = GetIdToNameMap();
        private static readonly Dictionary<string, T> namesToValues = Invert(valueToNames);

        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string text = reader.GetString();

            if (namesToValues.TryGetValue(reader.GetString(), out T value))
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
            writer.WriteStringValue(valueToNames[value]);
        }

        private static Dictionary<string, T> Invert(Dictionary<T, string> map)
        {
            var result = new Dictionary<string, T>(map.Count, StringComparer.OrdinalIgnoreCase);

            foreach (var item in map)
            {
                result[item.Value] = item.Key;
            }

            return result;
        }

        private static Dictionary<T, string> GetIdToNameMap()
        {
            var dic = new Dictionary<T, string>();

            foreach (var field in typeof(T).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                var description = field.GetCustomAttribute<EnumMemberAttribute>(false);

                var value = (T)field.GetValue(null);

                dic[value] = description is not null ? description.Value : value.ToString();
            }

            return dic;
        }
    }
}
