using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib
{
    /// <summary>
    /// Custom Converter for encoding/encoding byte[] using Base64Url instead of default Base64.
    /// </summary>
    public class Base64UrlConverter : JsonConverter<byte[]>
    {
        private readonly bool _allowNull = false;

        public Base64UrlConverter()
        {
        }

        public Base64UrlConverter(bool allowNull = false)
        {
            _allowNull = allowNull;
        }

        public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(Base64Url.Encode(value));
        }

        public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            byte[] ret = null;

            if (JsonTokenType.Null == reader.TokenType && _allowNull)
                return ret;

            if (JsonTokenType.Null == reader.TokenType)
                throw new Fido2VerificationException("json value must not be null");
            if (JsonTokenType.String != reader.TokenType)
                throw new Fido2VerificationException("json valuetype must be string");
            try
            {
                ret = Base64Url.Decode(reader.GetString());
            }
            catch (FormatException ex)
            {
                throw new Fido2VerificationException("json value must be valid base64 encoded string", ex);
            }
            return ret;
        }
    }

    public sealed class NullableBase64UrlConverter : Base64UrlConverter
    {
        public NullableBase64UrlConverter()
            : base(true)
        {

        }
    }
}
