using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.Serialization;

namespace Fido2NetLib
{
    public static class EnumNameMapper<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] TEnum>
        where TEnum: struct, Enum
    {
        private static readonly Dictionary<TEnum, string> valueToNames = GetIdToNameMap();
        private static readonly Dictionary<string, TEnum> namesToValues = Invert(valueToNames);

        private static Dictionary<string, TEnum> Invert(Dictionary<TEnum, string> map)
        {
            var result = new Dictionary<string, TEnum>(map.Count, StringComparer.OrdinalIgnoreCase);

            foreach (var item in map)
            {
                result[item.Value] = item.Key;
            }

            return result;
        }

        public static bool TryGetValue(string name, bool ignoreCase, out TEnum value)
        {
            if (namesToValues.TryGetValue(name, out value))
            {
                if (!ignoreCase && !valueToNames[value].Equals(name, StringComparison.Ordinal))
                {
                    value = default;

                    return false;
                }
                else
                {
                    return true;
                }
            }
            else
            {
                value = default;

                return false;
            }
        }

        public static bool TryGetValue(string name, out TEnum value)
        {
            return namesToValues.TryGetValue(name, out value);
        }

        public static string GetName(TEnum value)
        {
            return valueToNames[value];
        }

        public static IEnumerable<string> GetNames()
        {
            return namesToValues.Keys;
        }

        private static Dictionary<TEnum, string> GetIdToNameMap()
        {
            var dic = new Dictionary<TEnum, string>();

            foreach (var field in typeof(TEnum).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                var description = field.GetCustomAttribute<EnumMemberAttribute>(false);

                var value = (TEnum)field.GetValue(null);

                dic[value] = description is not null ? description.Value : value.ToString();
            }

            return dic;
        }
    }
}
