using System.Text.Json;

namespace Fido2NetLib;

internal static class JsonElementExtensions
{
    public static string[] ToStringArray(this in JsonElement el)
    {
        var result = new string[el.GetArrayLength()];

        int i = 0;

        foreach (var item in el.EnumerateArray())
        {
            result[i] = item.GetString()!;

            i++;
        }

        return result;
    }
}
