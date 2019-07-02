/*
Written by Peter O. in 2013.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using System.IO;
using System.Text;

namespace PeterO {
    /// <include file='../docs.xml'
    /// path='docs/doc[@name="T:PeterO.DataUtilities"]/*'/>
  public static class DataUtilities {
    private const int StreamedStringBufferLength = 4096;

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.GetUtf8String(System.Byte[],System.Boolean)"]/*'/>
    public static string GetUtf8String(byte[] bytes, bool replace) {
      if (bytes == null) {
        throw new ArgumentNullException(nameof(bytes));
      }
      var b = new StringBuilder();
      if (ReadUtf8FromBytes(bytes, 0, bytes.Length, b, replace) != 0) {
        throw new ArgumentException("Invalid UTF-8");
      }
      return b.ToString();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.CodePointLength(System.String)"]/*'/>
    public static int CodePointLength(string str) {
      if (str == null) {
        throw new ArgumentNullException(nameof(str));
      }
      var i = 0;
      var count = 0;
     while (i < str.Length) {
       int c = CodePointAt(str, i);
       ++count;
       i += (c >= 0x10000) ? 2 : 1;
     }
     return count;
}

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.GetUtf8String(System.Byte[],System.Int32,System.Int32,System.Boolean)"]/*'/>
    public static string GetUtf8String(
  byte[] bytes,
  int offset,
  int bytesCount,
  bool replace) {
      if (bytes == null) {
        throw new ArgumentNullException(nameof(bytes));
      }
      if (offset < 0) {
        throw new ArgumentException("offset (" + offset + ") is less than " +
                    "0");
      }
      if (offset > bytes.Length) {
        throw new ArgumentException("offset (" + offset + ") is more than " +
                    bytes.Length);
      }
      if (bytesCount < 0) {
        throw new ArgumentException("bytesCount (" + bytesCount +
                    ") is less than 0");
      }
      if (bytesCount > bytes.Length) {
        throw new ArgumentException("bytesCount (" + bytesCount +
                    ") is more than " + bytes.Length);
      }
      if (bytes.Length - offset < bytesCount) {
        throw new ArgumentException("bytes's length minus " + offset + " (" +
                (bytes.Length - offset) + ") is less than " + bytesCount);
      }
      var b = new StringBuilder();
      if (ReadUtf8FromBytes(bytes, offset, bytesCount, b, replace) != 0) {
        throw new ArgumentException("Invalid UTF-8");
      }
      return b.ToString();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.GetUtf8Bytes(System.String,System.Boolean)"]/*'/>
        public static byte[] GetUtf8Bytes(string str, bool replace) {
          return GetUtf8Bytes(str, replace, false);
        }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.GetUtf8Bytes(System.String,System.Boolean,System.Boolean)"]/*'/>
    public static byte[] GetUtf8Bytes(
  string str,
  bool replace,
  bool lenientLineBreaks) {
      if (str == null) {
        throw new ArgumentNullException(nameof(str));
      }
      if (!lenientLineBreaks && str.Length == 1) {
        int c = str[0];
        if ((c & 0xf800) == 0xd800) {
          if (replace) {
 c = 0xfffd;
} else {
 throw new ArgumentException("Unpaired surrogate code point");
}
        }
        if (c <= 0x80) {
          return new byte[] { (byte)c };
        } else if (c <= 0x7ff) {
          return new byte[] { (byte)(0xc0 | ((c >> 6) & 0x1f)),
            (byte)(0x80 | (c & 0x3f)) };
        } else {
          return new byte[] { (byte)(0xe0 | ((c >> 12) & 0x0f)),
            (byte)(0x80 | ((c >> 6) & 0x3f)),
            (byte)(0x80 | (c & 0x3f)) };
        }
      } else if (str.Length == 2) {
        int c = str[0];
        int c2 = str[1];
        if ((c & 0xfc00) == 0xd800 && (c2 & 0xfc00) == 0xdc00) {
          c = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
          return new byte[] { (byte)(0xf0 | ((c >> 18) & 0x07)),
            (byte)(0x80 | ((c >> 12) & 0x3f)),
            (byte)(0x80 | ((c >> 6) & 0x3f)),
            (byte)(0x80 | (c & 0x3f)) };
        } else if (!lenientLineBreaks && c <= 0x80 && c2 <= 0x80) {
          return new byte[] { (byte)c, (byte)c2 };
        }
      }
      try {
        using (var ms = new MemoryStream()) {
       if (WriteUtf8(str, 0, str.Length, ms, replace, lenientLineBreaks) !=
            0) {
            throw new ArgumentException("Unpaired surrogate code point");
          }
          return ms.ToArray();
        }
      } catch (IOException ex) {
        throw new ArgumentException("I/O error occurred", ex);
      }
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.GetUtf8Length(System.String,System.Boolean)"]/*'/>
    public static long GetUtf8Length(string str, bool replace) {
      if (str == null) {
        throw new ArgumentNullException(nameof(str));
      }
      long size = 0;
      for (var i = 0; i < str.Length; ++i) {
        int c = str[i];
        if (c <= 0x7f) {
          ++size;
        } else if (c <= 0x7ff) {
          size += 2;
        } else if (c <= 0xd7ff || c >= 0xe000) {
          size += 3;
        } else if (c <= 0xdbff) {  // UTF-16 leading surrogate
          ++i;
          if (i >= str.Length || str[i] < 0xdc00 || str[i] > 0xdfff) {
            if (replace) {
              size += 3;
              --i;
            } else {
              return -1;
            }
          } else {
            size += 4;
          }
        } else {
          if (replace) {
            size += 3;
          } else {
            return -1;
          }
        }
      }
      return size;
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.CodePointBefore(System.String,System.Int32)"]/*'/>
    public static int CodePointBefore(string str, int index) {
      return CodePointBefore(str, index, 0);
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.CodePointBefore(System.String,System.Int32,System.Int32)"]/*'/>
    public static int CodePointBefore(
  string str,
  int index,
  int surrogateBehavior) {
      if (str == null) {
        throw new ArgumentNullException(nameof(str));
      }
      if (index <= 0) {
        return -1;
      }
      if (index > str.Length) {
        return -1;
      }
      int c = str[index - 1];
      if ((c & 0xfc00) == 0xdc00 && index - 2 >= 0 &&
          (str[index - 2] & 0xfc00) == 0xd800) {
        // Get the Unicode code point for the surrogate pair
        return 0x10000 + ((str[index - 2] - 0xd800) << 10) + (c - 0xdc00);
      }
      if ((c & 0xf800) == 0xd800) {
        // unpaired surrogate
        return (surrogateBehavior == 0) ? 0xfffd : ((surrogateBehavior == 1) ?
                    c : (-1));
      }
      return c;
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.CodePointAt(System.String,System.Int32)"]/*'/>
    public static int CodePointAt(string str, int index) {
      return CodePointAt(str, index, 0);
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.CodePointAt(System.String,System.Int32,System.Int32)"]/*'/>
    public static int CodePointAt(
  string str,
  int index,
  int surrogateBehavior) {
      if (str == null) {
        throw new ArgumentNullException(nameof(str));
      }
      if (index >= str.Length) {
        return -1;
      }
      if (index < 0) {
        return -1;
      }
      int c = str[index];
      if ((c & 0xfc00) == 0xd800 && index + 1 < str.Length &&
          (str[index + 1] & 0xfc00) == 0xdc00) {
        // Get the Unicode code point for the surrogate pair
        c = 0x10000 + ((c - 0xd800) << 10) + (str[index + 1] - 0xdc00);
        ++index;
      } else if ((c & 0xf800) == 0xd800) {
        // unpaired surrogate
        return (surrogateBehavior == 0) ? 0xfffd : ((surrogateBehavior == 1) ?
                    c : (-1));
      }
      return c;
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.ToLowerCaseAscii(System.String)"]/*'/>
    public static string ToLowerCaseAscii(string str) {
      if (str == null) {
        return null;
      }
      var len = str.Length;
      var c = (char)0;
      var hasUpperCase = false;
      for (var i = 0; i < len; ++i) {
        c = str[i];
        if (c >= 'A' && c <= 'Z') {
          hasUpperCase = true;
          break;
        }
      }
      if (!hasUpperCase) {
        return str;
      }
      var builder = new StringBuilder();
      for (var i = 0; i < len; ++i) {
        c = str[i];
        if (c >= 'A' && c <= 'Z') {
          builder.Append((char)(c + 0x20));
        } else {
          builder.Append(c);
        }
      }
      return builder.ToString();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.ToUpperCaseAscii(System.String)"]/*'/>
    public static string ToUpperCaseAscii(string str) {
      if (str == null) {
        return null;
      }
      var len = str.Length;
      var c = (char)0;
      var hasLowerCase = false;
      for (var i = 0; i < len; ++i) {
        c = str[i];
        if (c >= 'a' && c <= 'z') {
          hasLowerCase = true;
          break;
        }
      }
      if (!hasLowerCase) {
        return str;
      }
      var builder = new StringBuilder();
      for (var i = 0; i < len; ++i) {
        c = str[i];
        if (c >= 'a' && c <= 'z') {
          builder.Append((char)(c - 0x20));
        } else {
          builder.Append(c);
        }
      }
      return builder.ToString();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.CodePointCompare(System.String,System.String)"]/*'/>
    public static int CodePointCompare(string strA, string strB) {
      if (strA == null) {
        return (strB == null) ? 0 : -1;
      }
      if (strB == null) {
        return 1;
      }
      int len, ca, cb;
      len = Math.Min(strA.Length, strB.Length);
      for (var i = 0; i < len; ++i) {
         ca = strA[i];
         cb = strB[i];
        if (ca == cb) {
          // normal code units and illegal surrogates
          // are treated as single code points
          if ((ca & 0xf800) != 0xd800) {
            continue;
          }
          var incindex = false;
          if (i + 1 < strA.Length && (strA[i + 1] & 0xfc00) == 0xdc00) {
            ca = 0x10000 + ((ca - 0xd800) << 10) + (strA[i + 1] - 0xdc00);
            incindex = true;
          }
          if (i + 1 < strB.Length && (strB[i + 1] & 0xfc00) == 0xdc00) {
            cb = 0x10000 + ((cb - 0xd800) << 10) + (strB[i + 1] - 0xdc00);
            incindex = true;
          }
          if (ca != cb) {
            return ca - cb;
          }
          if (incindex) {
            ++i;
          }
        } else {
          if ((ca & 0xf800) != 0xd800 && (cb & 0xf800) != 0xd800) {
            return ca - cb;
          }
          if ((ca & 0xfc00) == 0xd800 && i + 1 < strA.Length &&
              (strA[i + 1] & 0xfc00) == 0xdc00) {
            ca = 0x10000 + ((ca - 0xd800) << 10) + (strA[i + 1] - 0xdc00);
          }
          if ((cb & 0xfc00) == 0xd800 && i + 1 < strB.Length &&
              (strB[i + 1] & 0xfc00) == 0xdc00) {
            cb = 0x10000 + ((cb - 0xd800) << 10) + (strB[i + 1] - 0xdc00);
          }
          return ca - cb;
        }
      }
      return (strA.Length == strB.Length) ? 0 : ((strA.Length < strB.Length) ?
                    -1 : 1);
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.WriteUtf8(System.String,System.Int32,System.Int32,System.IO.Stream,System.Boolean)"]/*'/>
    public static int WriteUtf8(
  string str,
  int offset,
  int length,
  Stream stream,
  bool replace) {
      return WriteUtf8(str, offset, length, stream, replace, false);
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.WriteUtf8(System.String,System.Int32,System.Int32,System.IO.Stream,System.Boolean,System.Boolean)"]/*'/>
    public static int WriteUtf8(
  string str,
  int offset,
  int length,
  Stream stream,
  bool replace,
  bool lenientLineBreaks) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (str == null) {
        throw new ArgumentNullException(nameof(str));
      }
      if (offset < 0) {
        throw new ArgumentException("offset (" + offset + ") is less than " +
                    "0");
      }
      if (offset > str.Length) {
        throw new ArgumentException("offset (" + offset + ") is more than " +
                    str.Length);
      }
      if (length < 0) {
        throw new ArgumentException("length (" + length + ") is less than " +
                    "0");
      }
      if (length > str.Length) {
        throw new ArgumentException("length (" + length + ") is more than " +
                    str.Length);
      }
      if (str.Length - offset < length) {
        throw new ArgumentException("str.Length minus offset (" +
                (str.Length - offset) + ") is less than " + length);
      }
      int endIndex, c;
      byte[] bytes;
      var retval = 0;
      bytes = new byte[StreamedStringBufferLength];
      var byteIndex = 0;
       endIndex = offset + length;
      for (int index = offset; index < endIndex; ++index) {
         c = str[index];
        if (c <= 0x7f) {
          if (lenientLineBreaks) {
            if (c == 0x0d && (index + 1 >= endIndex || str[index + 1] !=
                    0x0a)) {
              // bare CR, convert to CRLF
              if (byteIndex + 2 > StreamedStringBufferLength) {
                // Write bytes retrieved so far
                stream.Write(bytes, 0, byteIndex);
                byteIndex = 0;
              }
              bytes[byteIndex++] = 0x0d;
              bytes[byteIndex++] = 0x0a;
              continue;
            } else if (c == 0x0d) {
              // CR-LF pair
              if (byteIndex + 2 > StreamedStringBufferLength) {
                // Write bytes retrieved so far
                stream.Write(bytes, 0, byteIndex);
                byteIndex = 0;
              }
              bytes[byteIndex++] = 0x0d;
              bytes[byteIndex++] = 0x0a;
              ++index;
              continue;
            }
            if (c == 0x0a) {
              // bare LF, convert to CRLF
              if (byteIndex + 2 > StreamedStringBufferLength) {
                // Write bytes retrieved so far
                stream.Write(bytes, 0, byteIndex);
                byteIndex = 0;
              }
              bytes[byteIndex++] = 0x0d;
              bytes[byteIndex++] = 0x0a;
              continue;
            }
          }
          if (byteIndex >= StreamedStringBufferLength) {
            // Write bytes retrieved so far
            stream.Write(bytes, 0, byteIndex);
            byteIndex = 0;
          }
          bytes[byteIndex++] = (byte)c;
        } else if (c <= 0x7ff) {
          if (byteIndex + 2 > StreamedStringBufferLength) {
            // Write bytes retrieved so far
            stream.Write(bytes, 0, byteIndex);
            byteIndex = 0;
          }
          bytes[byteIndex++] = (byte)(0xc0 | ((c >> 6) & 0x1f));
          bytes[byteIndex++] = (byte)(0x80 | (c & 0x3f));
        } else {
          if ((c & 0xfc00) == 0xd800 && index + 1 < endIndex &&
              (str[index + 1] & 0xfc00) == 0xdc00) {
            // Get the Unicode code point for the surrogate pair
            c = 0x10000 + ((c - 0xd800) << 10) + (str[index + 1] - 0xdc00);
            ++index;
          } else if ((c & 0xf800) == 0xd800) {
            // unpaired surrogate
            if (!replace) {
              retval = -1;
              break;  // write bytes read so far
            }
            c = 0xfffd;
          }
          if (c <= 0xffff) {
            if (byteIndex + 3 > StreamedStringBufferLength) {
              // Write bytes retrieved so far
              stream.Write(bytes, 0, byteIndex);
              byteIndex = 0;
            }
            bytes[byteIndex++] = (byte)(0xe0 | ((c >> 12) & 0x0f));
            bytes[byteIndex++] = (byte)(0x80 | ((c >> 6) & 0x3f));
            bytes[byteIndex++] = (byte)(0x80 | (c & 0x3f));
          } else {
            if (byteIndex + 4 > StreamedStringBufferLength) {
              // Write bytes retrieved so far
              stream.Write(bytes, 0, byteIndex);
              byteIndex = 0;
            }
            bytes[byteIndex++] = (byte)(0xf0 | ((c >> 18) & 0x07));
            bytes[byteIndex++] = (byte)(0x80 | ((c >> 12) & 0x3f));
            bytes[byteIndex++] = (byte)(0x80 | ((c >> 6) & 0x3f));
            bytes[byteIndex++] = (byte)(0x80 | (c & 0x3f));
          }
        }
      }
      stream.Write(bytes, 0, byteIndex);
      return retval;
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.WriteUtf8(System.String,System.IO.Stream,System.Boolean)"]/*'/>
    public static int WriteUtf8(string str, Stream stream, bool replace) {
      if (str == null) {
        throw new ArgumentNullException(nameof(str));
      }
      return WriteUtf8(str, 0, str.Length, stream, replace);
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.ReadUtf8FromBytes(System.Byte[],System.Int32,System.Int32,System.Text.StringBuilder,System.Boolean)"]/*'/>
    public static int ReadUtf8FromBytes(
  byte[] data,
  int offset,
  int bytesCount,
  StringBuilder builder,
  bool replace) {
      if (data == null) {
        throw new ArgumentNullException(nameof(data));
      }
      if (offset < 0) {
        throw new ArgumentException("offset (" + offset + ") is less than " +
                    "0");
      }
      if (offset > data.Length) {
        throw new ArgumentException("offset (" + offset + ") is more than " +
                    data.Length);
      }
      if (bytesCount < 0) {
        throw new ArgumentException("bytesCount (" + bytesCount +
                    ") is less than 0");
      }
      if (bytesCount > data.Length) {
        throw new ArgumentException("bytesCount (" + bytesCount +
                    ") is more than " + data.Length);
      }
      if (data.Length - offset < bytesCount) {
        throw new ArgumentException("data.Length minus offset (" +
                (data.Length - offset) + ") is less than " + bytesCount);
      }
      if (builder == null) {
        throw new ArgumentNullException(nameof(builder));
      }
      var cp = 0;
      var bytesSeen = 0;
      var bytesNeeded = 0;
      var lower = 0x80;
      var upper = 0xbf;
      int pointer, endpointer, b;
       pointer = offset;
       endpointer = offset + bytesCount;
      while (pointer < endpointer) {
         b = data[pointer] & (int)0xff;
        ++pointer;
        if (bytesNeeded == 0) {
          if ((b & 0x7f) == b) {
            builder.Append((char)b);
          } else if (b >= 0xc2 && b <= 0xdf) {
            bytesNeeded = 1;
            cp = (b - 0xc0) << 6;
          } else if (b >= 0xe0 && b <= 0xef) {
            lower = (b == 0xe0) ? 0xa0 : 0x80;
            upper = (b == 0xed) ? 0x9f : 0xbf;
            bytesNeeded = 2;
            cp = (b - 0xe0) << 12;
          } else if (b >= 0xf0 && b <= 0xf4) {
            lower = (b == 0xf0) ? 0x90 : 0x80;
            upper = (b == 0xf4) ? 0x8f : 0xbf;
            bytesNeeded = 3;
            cp = (b - 0xf0) << 18;
          } else {
            if (replace) {
              builder.Append((char)0xfffd);
            } else {
              return -1;
            }
          }
          continue;
        }
        if (b < lower || b > upper) {
          cp = bytesNeeded = bytesSeen = 0;
          lower = 0x80;
          upper = 0xbf;
          if (replace) {
            --pointer;
            builder.Append((char)0xfffd);
            continue;
          }
          return -1;
        } else {
          lower = 0x80;
          upper = 0xbf;
          ++bytesSeen;
          cp += (b - 0x80) << (6 * (bytesNeeded - bytesSeen));
          if (bytesSeen != bytesNeeded) {
            continue;
          }
          int ret, ch, lead, trail;
           ret = cp;
          cp = 0;
          bytesSeen = 0;
          bytesNeeded = 0;
          if (ret <= 0xffff) {
            builder.Append((char)ret);
          } else {
             ch = ret - 0x10000;
             lead = (ch >> 10) + 0xd800;
             trail = (ch & 0x3ff) + 0xdc00;
            builder.Append((char)lead);
            builder.Append((char)trail);
          }
        }
      }
      if (bytesNeeded != 0) {
        if (replace) {
          builder.Append((char)0xfffd);
        } else {
          return -1;
        }
      }
      return 0;
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.ReadUtf8ToString(System.IO.Stream)"]/*'/>
    public static string ReadUtf8ToString(Stream stream) {
      return ReadUtf8ToString(stream, -1, true);
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.ReadUtf8ToString(System.IO.Stream,System.Int32,System.Boolean)"]/*'/>
    public static string ReadUtf8ToString(
  Stream stream,
  int bytesCount,
  bool replace) {
      var builder = new StringBuilder();
      if (DataUtilities.ReadUtf8(stream, bytesCount, builder, replace) == -1) {
        throw new IOException(
       "Unpaired surrogate code point found.",
       new ArgumentException("Unpaired surrogate code point found."));
      }
      return builder.ToString();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.DataUtilities.ReadUtf8(System.IO.Stream,System.Int32,System.Text.StringBuilder,System.Boolean)"]/*'/>
    public static int ReadUtf8(
  Stream stream,
  int bytesCount,
  StringBuilder builder,
  bool replace) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (builder == null) {
        throw new ArgumentNullException(nameof(builder));
      }
      int b;
      var cp = 0;
      var bytesSeen = 0;
      var bytesNeeded = 0;
      var lower = 0x80;
      var upper = 0xbf;
      var pointer = 0;
      while (pointer < bytesCount || bytesCount < 0) {
        b = stream.ReadByte();
        if (b < 0) {
          if (bytesNeeded != 0) {
            bytesNeeded = 0;
            if (replace) {
              builder.Append((char)0xfffd);
              if (bytesCount >= 0) {
                return -2;
              }
              break;  // end of stream
            }
            return -1;
          }
          if (bytesCount >= 0) {
            return -2;
          }
          break;  // end of stream
        }
        if (bytesCount > 0) {
          ++pointer;
        }
        if (bytesNeeded == 0) {
          if ((b & 0x7f) == b) {
            builder.Append((char)b);
          } else if (b >= 0xc2 && b <= 0xdf) {
            bytesNeeded = 1;
            cp = (b - 0xc0) << 6;
          } else if (b >= 0xe0 && b <= 0xef) {
            lower = (b == 0xe0) ? 0xa0 : 0x80;
            upper = (b == 0xed) ? 0x9f : 0xbf;
            bytesNeeded = 2;
            cp = (b - 0xe0) << 12;
          } else if (b >= 0xf0 && b <= 0xf4) {
            lower = (b == 0xf0) ? 0x90 : 0x80;
            upper = (b == 0xf4) ? 0x8f : 0xbf;
            bytesNeeded = 3;
            cp = (b - 0xf0) << 18;
          } else {
            if (replace) {
              builder.Append((char)0xfffd);
            } else {
              return -1;
            }
          }
          continue;
        }
        if (b < lower || b > upper) {
          cp = bytesNeeded = bytesSeen = 0;
          lower = 0x80;
          upper = 0xbf;
          if (replace) {
            builder.Append((char)0xfffd);
            // "Read" the last byte again
            if (b < 0x80) {
              builder.Append((char)b);
            } else if (b >= 0xc2 && b <= 0xdf) {
              bytesNeeded = 1;
              cp = (b - 0xc0) << 6;
            } else if (b >= 0xe0 && b <= 0xef) {
              lower = (b == 0xe0) ? 0xa0 : 0x80;
              upper = (b == 0xed) ? 0x9f : 0xbf;
              bytesNeeded = 2;
              cp = (b - 0xe0) << 12;
            } else if (b >= 0xf0 && b <= 0xf4) {
              lower = (b == 0xf0) ? 0x90 : 0x80;
              upper = (b == 0xf4) ? 0x8f : 0xbf;
              bytesNeeded = 3;
              cp = (b - 0xf0) << 18;
            } else {
              builder.Append((char)0xfffd);
            }
            continue;
          }
          return -1;
        } else {
          lower = 0x80;
          upper = 0xbf;
          ++bytesSeen;
          cp += (b - 0x80) << (6 * (bytesNeeded - bytesSeen));
          if (bytesSeen != bytesNeeded) {
            continue;
          }
          int ret, ch, lead, trail;
          ret = cp;
          cp = 0;
          bytesSeen = 0;
          bytesNeeded = 0;
          if (ret <= 0xffff) {
            builder.Append((char)ret);
          } else {
             ch = ret - 0x10000;
             lead = (ch >> 10) + 0xd800;
             trail = (ch & 0x3ff) + 0xdc00;
            builder.Append((char)lead);
            builder.Append((char)trail);
          }
        }
      }
      if (bytesNeeded != 0) {
        if (replace) {
          builder.Append((char)0xfffd);
        } else {
          return -1;
        }
      }
      return 0;
    }
  }
}
