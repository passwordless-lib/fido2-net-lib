using System;
using System.Reflection;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class ToStringJsonConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return true;
        }

        //public override object ReadJson(JsonReader reader, Type objectType, object existingValue, bool hasExistingValue, JsonSerializer serializer)
        //{
        //    //MethodInfo parse = objectType.GetMethod("Parse", new Type[] { typeof(string) });
        //    var p = objectType.GetConstructor(new[] { typeof(string) });
        //    if (p!= null)
        //    {
        //        return p.Invoke(new object[] { (string)reader.Value });
        //    }
        //}

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            var p = objectType.GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,null, new[] { typeof(string) },null);
            if (p != null)
            {
                return p.Invoke(new object[] { (string)reader.Value });
            }

            return null;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.WriteValue(value.ToString());

        }


        //public override TypedString ReadJson(JsonReader reader, Type objectType, TypedString existingValue, bool hasExistingValue, JsonSerializer serializer)
        //{
        //    objectType.GetConstructor() reader.Value
        //}
    }
}
