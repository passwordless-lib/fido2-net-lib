using System;
using System.Text;

namespace Fido2NetLib.Ctap2.Tests;

public class TestHelper
{
    public static FidoDeviceResponse GetResponse(ReadOnlySpan<char> text)
    {
        return new FidoDeviceResponse(Convert.FromHexString(GetCborEncodedHexString(text)));
    }

    public static string GetCborEncodedHexString(ReadOnlySpan<char> text)
    {
        var sb = new StringBuilder();

        foreach (ReadOnlySpan<char> line in text.EnumerateLines())
        {
            var normalizedLine = line;

            int poundIndex = line.IndexOf('#');

            if (poundIndex > -1)
            {
                normalizedLine = normalizedLine[..poundIndex];
            }

            sb.Append(normalizedLine.Trim());
        }

        // Remove spaces
        sb.Replace(" ", "");

        return sb.ToString();
    }
}
