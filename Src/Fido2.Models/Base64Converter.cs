using System;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// Custom Converter for encoding/encoding byte[] using Base64Url instead of default Base64.
    /// </summary>
    public class Base64UrlConverter : JsonConverter<byte[]>
    {
        private readonly Required _requirement = Required.DisallowNull;

        public Base64UrlConverter()
        {
        }

        public Base64UrlConverter(Required required = Required.DisallowNull)
        {
            _requirement = required;
        }

        public override void WriteJson(JsonWriter writer, byte[] value, JsonSerializer serializer)
        {
            writer.WriteValue(Base64Url.Encode(value));
        }

        public override byte[] ReadJson(JsonReader reader, Type objectType, byte[] existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            byte[] ret = null;

            if (null == reader.Value && _requirement == Required.AllowNull)
                return ret;

            if (null == reader.Value)
                throw new Fido2VerificationException("json value must not be null");
            if (Type.GetType("System.String") != reader.ValueType)
                throw new Fido2VerificationException("json valuetype must be string");
            try
            {
                ret = Base64Url.Decode((string)reader.Value);
            }
            catch (FormatException ex)
            {
                throw new Fido2VerificationException("json value must be valid base64 encoded string", ex);
            }
            return ret;
        }
    }
}
