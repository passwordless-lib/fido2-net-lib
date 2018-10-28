/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using System.IO;
using System.Text;
using PeterO;
using PeterO.Numbers;

namespace PeterO.Cbor {
  internal sealed class StringOutput {
    private readonly StringBuilder builder;
    private readonly Stream outputStream;

    public StringOutput(StringBuilder builder) {
      this.builder = builder;
      this.outputStream = null;
    }

    public StringOutput(Stream outputStream) {
      this.outputStream = outputStream;
      this.builder = null;
    }

    public void WriteString(string str) {
      if (this.outputStream != null) {
        if (str.Length == 1) {
          this.WriteCodePoint((int)str[0]);
        } else {
          if (DataUtilities.WriteUtf8(
            str,
            0,
            str.Length,
            this.outputStream,
            false) < 0) {
            throw new ArgumentException("str has an unpaired surrogate");
          }
        }
      } else {
        this.builder.Append(str);
      }
    }

    public void WriteString(string str, int index, int length) {
      if (this.outputStream != null) {
        if (length == 1) {
          this.WriteCodePoint((int)str[index]);
        } else {
          if (
  DataUtilities.WriteUtf8(
  str,
  index,
  length,
  this.outputStream,
  false) < 0) {
            throw new ArgumentException("str has an unpaired surrogate");
          }
        }
      } else {
        this.builder.Append(str, index, length);
      }
    }

    public void WriteCodePoint(int codePoint) {
      if (codePoint < 0) {
        throw new ArgumentException("codePoint (" + codePoint +
                ") is less than 0");
      }
      if (codePoint > 0x10ffff) {
        throw new ArgumentException("codePoint (" + codePoint +
                ") is more than " + 0x10ffff);
      }
      if (this.outputStream != null) {
        if (codePoint < 0x80) {
          this.outputStream.WriteByte((byte)codePoint);
        } else if (codePoint <= 0x7ff) {
          this.outputStream.WriteByte((byte)(0xc0 | ((codePoint >> 6) & 0x1f)));
          this.outputStream.WriteByte((byte)(0x80 | (codePoint & 0x3f)));
        } else if (codePoint <= 0xffff) {
          if ((codePoint & 0xf800) == 0xd800) {
            throw new ArgumentException("ch is a surrogate");
          }
          this.outputStream.WriteByte((byte)(0xe0 | ((codePoint >> 12) &
                    0x0f)));
          this.outputStream.WriteByte((byte)(0x80 | ((codePoint >> 6) & 0x3f)));
          this.outputStream.WriteByte((byte)(0x80 | (codePoint & 0x3f)));
        } else {
          this.outputStream.WriteByte((byte)(0xf0 | ((codePoint >> 18) &
                    0x08)));
          this.outputStream.WriteByte((byte)(0x80 | ((codePoint >> 12) &
                    0x3f)));
          this.outputStream.WriteByte((byte)(0x80 | ((codePoint >> 6) & 0x3f)));
          this.outputStream.WriteByte((byte)(0x80 | (codePoint & 0x3f)));
        }
      } else {
        if ((codePoint & 0xfff800) == 0xd800) {
          throw new ArgumentException("ch is a surrogate");
        }
        if (codePoint <= 0xffff) {
          { this.builder.Append((char)codePoint);
          }
        } else if (codePoint <= 0x10ffff) {
          this.builder.Append((char)((((codePoint - 0x10000) >> 10) &
                    0x3ff) + 0xd800));
          this.builder.Append((char)(((codePoint - 0x10000) & 0x3ff) + 0xdc00));
        }
      }
    }
  }
}
