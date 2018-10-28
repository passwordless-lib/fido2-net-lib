/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using System.Text;

namespace PeterO.Cbor {
  internal static class Base64 {
    private const string Base64URL =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    private const string Base64Classic =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    public static void WriteBase64(
  StringOutput writer,
  byte[] data,
  int offset,
  int count,
  bool padding) {
      WriteBase64(writer, data, offset, count, true, padding);
    }

    public static void WriteBase64URL(
  StringOutput writer,
  byte[] data,
  int offset,
  int count,
  bool padding) {
      WriteBase64(writer, data, offset, count, false, padding);
    }

    private static void WriteBase64(
  StringOutput writer,
  byte[] data,
  int offset,
  int count,
  bool classic,
  bool padding) {
      if (writer == null) {
        throw new ArgumentNullException(nameof(writer));
      }
      if (offset < 0) {
        throw new ArgumentException("offset (" + offset + ") is less than " +
                    "0 ");
      }
      if (offset > data.Length) {
        throw new ArgumentException("offset (" + offset + ") is more than " +
                    data.Length);
      }
      if (count < 0) {
        throw new ArgumentException("count (" + count + ") is less than " +
                    "0 ");
      }
      if (count > data.Length) {
        throw new ArgumentException("count (" + count + ") is more than " +
                    data.Length);
      }
      if (data.Length - offset < count) {
        throw new ArgumentException("data's length minus " + offset + " (" +
                (data.Length - offset) + ") is less than " + count);
      }
      string alphabet = classic ? Base64Classic : Base64URL;
      int length = offset + count;
      int i = offset;
      var buffer = new char[4];
      for (i = offset; i < (length - 2); i += 3) {
        buffer[0] = (char)alphabet[(data[i] >> 2) & 63];
        buffer[1] = (char)alphabet[((data[i] & 3) << 4) +
                ((data[i + 1] >> 4) & 15)];
        buffer[2] = (char)alphabet[((data[i + 1] & 15) << 2) + ((data[i +
                2] >> 6) & 3)];
        buffer[3] = (char)alphabet[data[i + 2] & 63];
        writer.WriteCodePoint((int)buffer[0]);
        writer.WriteCodePoint((int)buffer[1]);
        writer.WriteCodePoint((int)buffer[2]);
        writer.WriteCodePoint((int)buffer[3]);
      }
      int lenmod3 = count % 3;
      if (lenmod3 != 0) {
        i = length - lenmod3;
        buffer[0] = (char)alphabet[(data[i] >> 2) & 63];
        if (lenmod3 == 2) {
          buffer[1] = (char)alphabet[((data[i] & 3) << 4) + ((data[i + 1] >>
                4) & 15)];
          buffer[2] = (char)alphabet[(data[i + 1] & 15) << 2];
          writer.WriteCodePoint((int)buffer[0]);
          writer.WriteCodePoint((int)buffer[1]);
          writer.WriteCodePoint((int)buffer[2]);
          if (padding) {
            writer.WriteCodePoint((int)'=');
          }
        } else {
          buffer[1] = (char)alphabet[(data[i] & 3) << 4];
          writer.WriteCodePoint((int)buffer[0]);
          writer.WriteCodePoint((int)buffer[1]);
          if (padding) {
            writer.WriteCodePoint((int)'=');
            writer.WriteCodePoint((int)'=');
          }
        }
      }
    }
  }
}
