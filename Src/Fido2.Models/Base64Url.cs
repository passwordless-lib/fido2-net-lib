using System;
using System.Buffers;

namespace Fido2NetLib
{
    /// <summary>
    /// Helper class to handle Base64Url. Based on Carbon.Jose source code.
    /// </summary>
    public static class Base64Url
    {
        /// <summary>
        /// Converts arg data to a Base64Url encoded string.
        /// </summary>
        public static string Encode(ReadOnlySpan<byte> arg)
        {
            int base64Length = (int)(((long)arg.Length + 2) / 3 * 4);

            char[] pooledBuffer = ArrayPool<char>.Shared.Rent(base64Length);

            Convert.TryToBase64Chars(arg, pooledBuffer, out int encodedLength);

            Span<char> base64Url = pooledBuffer.AsSpan(0, encodedLength);

            for (int i = 0; i < base64Url.Length; i++)
            {
                ref char c = ref base64Url[i];

                switch (c)
                {
                    case '+': c = '-'; break;
                    case '/': c = '_'; break;
                }
            }

            int equalIndex = base64Url.IndexOf('=');

            if (equalIndex > -1) // remove trailing equal characters
            {
                base64Url = base64Url.Slice(0, equalIndex);
            }

            var result = new string(base64Url);

            ArrayPool<char>.Shared.Return(pooledBuffer, clearArray: true);

            return result;
        }

        /// <summary>
        /// Decodes a Base64Url encoded string to its raw bytes.
        /// </summary>
        public static byte[] Decode(string text)
        {
            if (text is null)
                throw new ArgumentNullException(nameof(text));

            int padCharCount = (text.Length % 4) switch
            {
                2 => 2,
                3 => 1,
                _ => 0
            };

            int encodedLength = text.Length + padCharCount;

            char[] buffer = ArrayPool<char>.Shared.Rent(encodedLength);

            text.CopyTo(0, buffer, 0, text.Length);

            for (int i = 0; i < text.Length; i++)
            {
                ref char c = ref buffer[i];

                switch (c)
                {
                    case '-': c = '+'; break;
                    case '_': c = '/'; break;
                }
            }

            if (padCharCount == 1)
            {
                buffer[encodedLength - 1] = '=';
            }
            else if (padCharCount == 2)
            {
                buffer[encodedLength - 1] = '=';
                buffer[encodedLength - 2] = '=';
            }

            var result = Convert.FromBase64CharArray(buffer, 0, encodedLength);

            ArrayPool<char>.Shared.Return(buffer, true);

            return result;
        }
    }
}
