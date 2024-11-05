using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.Serialization;

namespace Fido2NetLib;

public static class EnumNameMapper<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] TEnum>
    where TEnum : struct, Enum
{
    private static readonly FrozenDictionary<TEnum, string> s_valueToNames = GetIdToNameMap();
    private static readonly FrozenDictionary<string, TEnum> s_namesToValues = Invert(s_valueToNames);

    private static FrozenDictionary<string, TEnum> Invert(FrozenDictionary<TEnum, string> map)
    {
        var items = new KeyValuePair<string, TEnum>[map.Count];
        int i = 0;

        foreach (var item in map)
        {
            items[i++] = new(item.Value, item.Key);
        }

        return items.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
    }

    public static bool TryGetValue(string name, out TEnum value)
    {
        return s_namesToValues.TryGetValue(name, out value);
    }

    public static string GetName(TEnum value)
    {
        return s_valueToNames[value];
    }

    public static IEnumerable<string> GetNames()
    {
        return s_namesToValues.Keys;
    }

    private static FrozenDictionary<TEnum, string> GetIdToNameMap()
    {
        var items = new List<KeyValuePair<TEnum, string>>();

        foreach (var field in typeof(TEnum).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            var description = field.GetCustomAttribute<EnumMemberAttribute>(false);

            var value = (TEnum)field.GetValue(null);

            items.Add(new(value, description is not null ? description.Value : value.ToString()));
        }

        return items.ToFrozenDictionary();
    }
}
