using System.Diagnostics.CodeAnalysis;
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

    public static bool TryDecodeArrayOfBase64EncodedBytes(this in JsonElement el, [NotNullWhen(true)] out byte[][]? result)
    {
        if (el.ValueKind is JsonValueKind.Array)
        {
            result = new byte[el.GetArrayLength()][];

            int i = 0;

            try
            {
                foreach (var item in el.EnumerateArray())
                {
                    result[i++] = item.GetBytesFromBase64()!;
                }

                return true;
            }
            catch { }
        }

        result = null;

        return false;
    }
}
