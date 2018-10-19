/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using System.IO;

namespace PeterO.Cbor {
    // <include file='../../docs.xml'
    // path='docs/doc[@name="T:PeterO.Cbor.CharacterReader"]/*'/>
  internal sealed class CharacterReader : ICharacterInput {
    private readonly int mode;
    private readonly bool errorThrow;
    private readonly bool dontSkipUtf8Bom;
    private readonly string str;
    private readonly int strLength;
    private readonly IByteReader stream;

    private int offset;
    private ICharacterInput reader;

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.#ctor(System.String)"]/*'/>
    public CharacterReader(string str) : this(str, false, false) {
    }

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.#ctor(System.String,System.Boolean)"]/*'/>
    public CharacterReader(string str, bool skipByteOrderMark) :
      this(str, skipByteOrderMark, false) {
    }

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.#ctor(System.String,System.Boolean,System.Boolean)"]/*'/>
  public CharacterReader(
  string str,
  bool skipByteOrderMark,
  bool errorThrow) {
      if (str == null) {
        throw new ArgumentNullException(nameof(str));
      }
      this.strLength = str.Length;
      this.offset = (skipByteOrderMark && this.strLength > 0 && str[0] ==
        0xfeff) ? 1 : 0;
      this.str = str;
      this.errorThrow = errorThrow;
      this.mode = -1;
      this.dontSkipUtf8Bom = false;
      this.stream = null;
    }

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.#ctor(System.String,System.Int32,System.Int32)"]/*'/>
    public CharacterReader(string str, int offset, int length) :
      this(str, offset, length, false, false) {
    }

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.#ctor(System.String,System.Int32,System.Int32,System.Boolean,System.Boolean)"]/*'/>
    public CharacterReader(
  string str,
  int offset,
  int length,
  bool skipByteOrderMark,
  bool errorThrow) {
      if (str == null) {
  throw new ArgumentNullException(nameof(str));
}
if (offset < 0) {
  throw new ArgumentException("offset (" + offset +
    ") is less than 0");
}
if (offset > str.Length) {
  throw new ArgumentException("offset (" + offset +
    ") is more than " + str.Length);
}
if (length < 0) {
  throw new ArgumentException("length (" + length +
    ") is less than 0");
}
if (length > str.Length) {
  throw new ArgumentException("length (" + length +
    ") is more than " + str.Length);
}
if (str.Length - offset < length) {
  throw new ArgumentException("str's length minus " + offset + " (" +
    (str.Length - offset) + ") is less than " + length);
}
      this.strLength = length;
      this.offset = (skipByteOrderMark && length > 0 && str[offset] ==
        0xfeff) ? offset + 1 : 0;
      this.str = str;
      this.errorThrow = errorThrow;
      this.mode = -1;
      this.dontSkipUtf8Bom = false;
      this.stream = null;
    }

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.#ctor(System.IO.Stream)"]/*'/>
    public CharacterReader(Stream stream) : this(stream, 0, false) {
    }

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.#ctor(System.IO.Stream,System.Int32,System.Boolean)"]/*'/>
    public CharacterReader(Stream stream, int mode, bool errorThrow) :
      this(stream, mode, errorThrow, false) {
    }

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.#ctor(System.IO.Stream,System.Int32)"]/*'/>
    public CharacterReader(Stream stream, int mode) :
      this(stream, mode, false, false) {
    }

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.#ctor(System.IO.Stream,System.Int32,System.Boolean,System.Boolean)"]/*'/>
    public CharacterReader(
  Stream stream,
  int mode,
  bool errorThrow,
  bool dontSkipUtf8Bom) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      this.stream = new WrappedStream(stream);
      this.mode = mode;
      this.errorThrow = errorThrow;
      this.dontSkipUtf8Bom = dontSkipUtf8Bom;
      this.str = String.Empty;
      this.strLength = -1;
    }

    private interface IByteReader {
      int ReadByte();
    }

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.Read(System.Int32[],System.Int32,System.Int32)"]/*'/>
    public int Read(int[] chars, int index, int length) {
      if (chars == null) {
        throw new ArgumentNullException(nameof(chars));
      }
      if (index < 0) {
        throw new ArgumentException("index (" + index +
          ") is less than 0");
      }
      if (index > chars.Length) {
        throw new ArgumentException("index (" + index +
          ") is more than " + chars.Length);
      }
      if (length < 0) {
        throw new ArgumentException("length (" + length +
          ") is less than 0");
      }
      if (length > chars.Length) {
        throw new ArgumentException("length (" + length +
          ") is more than " + chars.Length);
      }
      if (chars.Length - index < length) {
        throw new ArgumentException("chars's length minus " + index + " (" +
          (chars.Length - index) + ") is less than " + length);
      }
      var count = 0;
      for (int i = 0; i < length; ++i) {
        int c = this.ReadChar();
        if (c < 0) {
          return count;
        }
        chars[index + i] = c;
        ++count;
      }
      return count;
    }

    // <include file='../../docs.xml'
    // path='docs/doc[@name="M:PeterO.Cbor.CharacterReader.ReadChar"]/*'/>
    public int ReadChar() {
      if (this.reader != null) {
        return this.reader.ReadChar();
      }
      if (this.stream != null) {
        return this.DetectUnicodeEncoding();
      } else {
        int c = (this.offset < this.strLength) ? this.str[this.offset] : -1;
        if ((c & 0xfc00) == 0xd800 && this.offset + 1 < this.strLength &&
                this.str[this.offset + 1] >= 0xdc00 && this.str[this.offset + 1]
                <= 0xdfff) {
          // Get the Unicode code point for the surrogate pair
          c = 0x10000 + ((c - 0xd800) << 10) + (this.str[this.offset + 1] -
          0xdc00);
          ++this.offset;
        } else if ((c & 0xf800) == 0xd800) {
          // unpaired surrogate
          if (this.errorThrow) {
 throw new InvalidOperationException("Unpaired surrogate code point");
} else {
 c = 0xfffd;
}
        }
        ++this.offset;
        return c;
      }
    }

    private int DetectUtf8Or16Or32(int c1) {
      int c2, c3, c4;
      if (c1 == 0xff || c1 == 0xfe) {
        // Start of a possible byte-order mark
        // FF FE 0 0 --> UTF-32LE
        // FF FE ... --> UTF-16LE
        // FE FF --> UTF-16BE
        c2 = this.stream.ReadByte();
        bool bigEndian = c1 == 0xfe;
        int otherbyte = bigEndian ? 0xff : 0xfe;
        if (c2 == otherbyte) {
          c3 = this.stream.ReadByte();
          c4 = this.stream.ReadByte();
          if (!bigEndian && c3 == 0 && c4 == 0) {
            this.reader = new Utf32Reader(this.stream, false, this.errorThrow);
            return this.reader.ReadChar();
          } else {
      var newReader = new Utf16Reader(
  this.stream,
  bigEndian,
  this.errorThrow);
            newReader.Unget(c3, c4);
            this.reader = newReader;
            return newReader.ReadChar();
          }
        }
        // Assume UTF-8 here, so the 0xff or 0xfe is invalid
        if (this.errorThrow) {
          throw new InvalidOperationException("Invalid Unicode stream");
        } else {
          var utf8reader = new Utf8Reader(this.stream, this.errorThrow);
          utf8reader.Unget(c2);
          this.reader = utf8reader;
          return 0xfffd;
        }
      } else if (c1 == 0 && this.mode == 4) {
        // Here, the relevant cases are:
        // 0 0 0 NZA --> UTF-32BE (if mode is 4)
        // 0 0 FE FF --> UTF-32BE
        // Anything else is treated as UTF-8
        c2 = this.stream.ReadByte();
        c3 = this.stream.ReadByte();
        c4 = this.stream.ReadByte();
        if (c2 == 0 &&
           ((c3 == 0xfe && c4 == 0xff) ||
            (c3 == 0 && c4 >= 0x01 && c4 <= 0x7f))) {
          this.reader = new Utf32Reader(this.stream, true, this.errorThrow);
          return c3 == 0 ? c4 : this.reader.ReadChar();
        } else {
          var utf8reader = new Utf8Reader(this.stream, this.errorThrow);
          utf8reader.UngetThree(c2, c3, c4);
          this.reader = utf8reader;
          return c1;
        }
      } else if (this.mode == 2) {
        if (c1 >= 0x01 && c1 <= 0x7f) {
          // Nonzero ASCII character
          c2 = this.stream.ReadByte();
          if (c2 == 0) {
            // NZA 0, so UTF-16LE or UTF-32LE
            c3 = this.stream.ReadByte();
            c4 = this.stream.ReadByte();
            if (c3 == 0 && c4 == 0) {
            this.reader = new Utf32Reader(
  this.stream,
  false,
  this.errorThrow);
              return c1;
            } else {
          var newReader = new Utf16Reader(
  this.stream,
  false,
  this.errorThrow);
              newReader.Unget(c3, c4);
              this.reader = newReader;
              return c1;
            }
          } else {
            // NZA NZ, so UTF-8
            var utf8reader = new Utf8Reader(this.stream, this.errorThrow);
            utf8reader.Unget(c2);
            this.reader = utf8reader;
            return c1;
          }
        } else if (c1 == 0) {
          // Zero
          c2 = this.stream.ReadByte();
          if (c2 >= 0x01 && c2 <= 0x7f) {
            // 0 NZA, so UTF-16BE
            var newReader = new Utf16Reader(this.stream, true, this.errorThrow);
            this.reader = newReader;
            return c2;
          } else if (c2 == 0) {
            // 0 0, so maybe UTF-32BE
            c3 = this.stream.ReadByte();
            c4 = this.stream.ReadByte();
            if (c3 == 0 && c4 >= 0x01 && c4 <= 0x7f) {
              // 0 0 0 NZA
              this.reader = new Utf32Reader(this.stream, true, this.errorThrow);
              return c4;
            } else if (c3 == 0xfe && c4 == 0xff) {
              // 0 0 FE FF
              this.reader = new Utf32Reader(this.stream, true, this.errorThrow);
              return this.reader.ReadChar();
            } else {
              // 0 0 ...
              var newReader = new Utf8Reader(this.stream, this.errorThrow);
              newReader.UngetThree(c2, c3, c4);
              this.reader = newReader;
              return c1;
            }
          } else {
            // 0 NonAscii, so UTF-8
            var utf8reader = new Utf8Reader(this.stream, this.errorThrow);
            utf8reader.Unget(c2);
            this.reader = utf8reader;
            return c1;
          }
        }
      }
      // Use default of UTF-8
      return -2;
    }

    private int DetectUtf8OrUtf16(int c1) {
      int mode = this.mode;
      int c2;
      if (c1 == 0xff || c1 == 0xfe) {
        c2 = this.stream.ReadByte();
        bool bigEndian = c1 == 0xfe;
        int otherbyte = bigEndian ? 0xff : 0xfe;
        if (c2 == otherbyte) {
      var newReader = new Utf16Reader(
  this.stream,
  bigEndian,
  this.errorThrow);
          this.reader = newReader;
          return newReader.ReadChar();
        }
        // Assume UTF-8 here, so the 0xff or 0xfe is invalid
        if (this.errorThrow) {
          throw new InvalidOperationException("Invalid Unicode stream");
        } else {
          var utf8reader = new Utf8Reader(this.stream, this.errorThrow);
          utf8reader.Unget(c2);
          this.reader = utf8reader;
          return 0xfffd;
        }
      } else if (mode == 1) {
        if (c1 >= 0x01 && c1 <= 0x7f) {
          // Nonzero ASCII character
          c2 = this.stream.ReadByte();
          if (c2 == 0) {
            // NZA 0, so UTF-16LE
          var newReader = new Utf16Reader(
  this.stream,
  false,
  this.errorThrow);
            this.reader = newReader;
          } else {
            // NZA NZ
            var utf8reader = new Utf8Reader(this.stream, this.errorThrow);
            utf8reader.Unget(c2);
            this.reader = utf8reader;
          }
          return c1;
        } else if (c1 == 0) {
          // Zero
          c2 = this.stream.ReadByte();
          if (c2 >= 0x01 && c2 <= 0x7f) {
            // 0 NZA, so UTF-16BE
            var newReader = new Utf16Reader(this.stream, true, this.errorThrow);
            this.reader = newReader;
            return c2;
          } else {
            var utf8reader = new Utf8Reader(this.stream, this.errorThrow);
            utf8reader.Unget(c2);
            this.reader = utf8reader;
            return c1;
          }
        }
      }
      // Use default of UTF-8
      return -2;
    }

    // Detects a Unicode encoding
    private int DetectUnicodeEncoding() {
      int mode = this.mode;
      int c1 = this.stream.ReadByte();
      int c2;
      if (c1 < 0) {
        return -1;
      }
      Utf8Reader utf8reader;
      if (mode == 0) {
        // UTF-8 only
        utf8reader = new Utf8Reader(this.stream, this.errorThrow);
        this.reader = utf8reader;
        c1 = utf8reader.ReadChar();
        if (c1 == 0xfeff) {
          // Skip BOM
          c1 = utf8reader.ReadChar();
        }
        return c1;
      } else if (mode == 1 || mode == 3) {
        c2 = this.DetectUtf8OrUtf16(c1);
        if (c2 >= -1) {
 return c2;
}
      } else if (mode == 2 || mode == 4) {
        // UTF-8, UTF-16, or UTF-32
        c2 = this.DetectUtf8Or16Or32(c1);
        if (c2 >= -1) {
 return c2;
}
      }
      // Default case: assume UTF-8
      utf8reader = new Utf8Reader(this.stream, this.errorThrow);
      this.reader = utf8reader;
      utf8reader.Unget(c1);
      c1 = utf8reader.ReadChar();
      if (!this.dontSkipUtf8Bom && c1 == 0xfeff) {
        // Skip BOM
        c1 = utf8reader.ReadChar();
      }
      return c1;
    }

    private sealed class SavedState {
      private int[] saved;
      private int savedLength;

      private void Ensure(int size) {
        this.saved = this.saved ?? (new int[this.savedLength + size]);
        if (this.savedLength + size < this.saved.Length) {
          var newsaved = new int[this.savedLength + size + 4];
          Array.Copy(this.saved, 0, newsaved, 0, this.savedLength);
          this.saved = newsaved;
        }
      }

      public void AddOne(int a) {
        this.Ensure(1);
        this.saved[this.savedLength++] = a;
      }

      public void AddTwo(int a, int b) {
        this.Ensure(2);
        this.saved[this.savedLength + 1] = a;
        this.saved[this.savedLength] = b;
        this.savedLength += 2;
      }

      public void AddThree(int a, int b, int c) {
        this.Ensure(3);
        this.saved[this.savedLength + 2] = a;
        this.saved[this.savedLength + 1] = b;
        this.saved[this.savedLength] = c;
        this.savedLength += 3;
      }

      public int Read(IByteReader input) {
        if (this.savedLength > 0) {
          int ret = this.saved[--this.savedLength];
          return ret;
        }
        return input.ReadByte();
      }
    }

    private sealed class Utf16Reader : ICharacterInput {
      private readonly bool bigEndian;
      private readonly IByteReader stream;
      private readonly SavedState state;
      private readonly bool errorThrow;

      public Utf16Reader(IByteReader stream, bool bigEndian, bool errorThrow) {
        this.stream = stream;
        this.bigEndian = bigEndian;
        this.state = new SavedState();
        this.errorThrow = errorThrow;
      }

      public void Unget(int c1, int c2) {
        this.state.AddTwo(c1, c2);
      }

      public int ReadChar() {
        int c1 = this.state.Read(this.stream);
        if (c1 < 0) {
          return -1;
        }
        int c2 = this.state.Read(this.stream);
        if (c2 < 0) {
          this.state.AddOne(-1);
          if (this.errorThrow) {
 throw new InvalidOperationException("Invalid UTF-16");
} else {
 return 0xfffd;
}
        }
        c1 = this.bigEndian ? ((c1 << 8) | c2) : ((c2 << 8) | c1);
        int surr = c1 & 0xfc00;
        if (surr == 0xd800) {
          surr = c1;
          c1 = this.state.Read(this.stream);
          c2 = this.state.Read(this.stream);
          if (c1 < 0 || c2 < 0) {
            this.state.AddOne(-1);
            if (this.errorThrow) {
 throw new InvalidOperationException("Invalid UTF-16");
} else {
 return 0xfffd;
}
          }
          int unit2 = this.bigEndian ? ((c1 << 8) | c2) : ((c2 << 8) | c1);
          if ((unit2 & 0xfc00) == 0xdc00) {
            return 0x10000 + ((surr - 0xd800) << 10) + (unit2 - 0xdc00);
          }
          this.Unget(c1, c2);
          if (this.errorThrow) {
 throw new InvalidOperationException("Invalid UTF-16");
} else {
 return 0xfffd;
}
        }
        if (surr == 0xdc00) {
          if (this.errorThrow) {
 throw new InvalidOperationException("Invalid UTF-16");
} else {
 return 0xfffd;
}
        }
        return c1;
      }

      public int Read(int[] chars, int index, int length) {
        var count = 0;
        for (int i = 0; i < length; ++i) {
          int c = this.ReadChar();
          if (c < 0) {
            return count;
          }
          chars[index + i] = c;
          ++count;
        }
        return count;
      }
    }

    private sealed class Utf32Reader : ICharacterInput {
      private readonly bool bigEndian;
      private readonly IByteReader stream;
      private readonly bool errorThrow;
      private readonly SavedState state;

      public Utf32Reader(IByteReader stream, bool bigEndian, bool errorThrow) {
        this.stream = stream;
        this.bigEndian = bigEndian;
        this.state = new SavedState();
        this.errorThrow = errorThrow;
      }

      public int ReadChar() {
        int c1 = this.state.Read(this.stream);
        if (c1 < 0) {
          return -1;
        }
        int c2 = this.state.Read(this.stream);
        int c3 = this.state.Read(this.stream);
        int c4 = this.state.Read(this.stream);
        if (c2 < 0 || c3 < 0 || c4 < 0) {
          this.state.AddOne(-1);
          if (this.errorThrow) {
 throw new InvalidOperationException("Invalid UTF-32");
} else {
 return 0xfffd;
}
        }
        c1 = this.bigEndian ? ((c1 << 24) | (c2 << 16) | (c3 << 8) | c4) :
          ((c4 << 24) | (c3 << 16) | (c2 << 8) | c1);
        if (c1 < 0 || c1 >= 0x110000 || (c1 & 0xfff800) == 0xd800) {
          if (this.errorThrow) {
 throw new InvalidOperationException("Invalid UTF-32");
} else {
 return 0xfffd;
}
        }
        return c1;
      }

      public int Read(int[] chars, int index, int length) {
        var count = 0;
        for (int i = 0; i < length; ++i) {
          int c = this.ReadChar();
          if (c < 0) {
            return count;
          }
          chars[index + i] = c;
          ++count;
        }
        return count;
      }
    }

    private sealed class Utf8Reader : ICharacterInput {
      private readonly IByteReader stream;
      private readonly SavedState state;
      private readonly bool errorThrow;
      private int lastChar;

      public Utf8Reader(IByteReader stream, bool errorThrow) {
        this.stream = stream;
        this.lastChar = -1;
        this.state = new SavedState();
        this.errorThrow = errorThrow;
      }

      public void Unget(int ch) {
        this.state.AddOne(ch);
      }

      public void UngetThree(int a, int b, int c) {
        this.state.AddThree(a, b, c);
      }

      public int ReadChar() {
        var cp = 0;
        var bytesSeen = 0;
        var bytesNeeded = 0;
        var lower = 0;
        var upper = 0;
        while (true) {
          int b;
          if (this.lastChar != -1) {
            b = this.lastChar;
            this.lastChar = -1;
          } else {
            b = this.state.Read(this.stream);
          }
          if (b < 0) {
            if (bytesNeeded != 0) {
              bytesNeeded = 0;
              if (this.errorThrow) {
 throw new InvalidOperationException("Invalid UTF-8");
} else {
 return 0xfffd;
}
            }
            return -1;
          }
          if (bytesNeeded == 0) {
            if ((b & 0x7f) == b) {
              return b;
            }
            if (b >= 0xc2 && b <= 0xdf) {
              bytesNeeded = 1;
              lower = 0x80;
              upper = 0xbf;
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
              if (this.errorThrow) {
 throw new InvalidOperationException("Invalid UTF-8");
} else {
 return 0xfffd;
}
            }
            continue;
          }
          if (b < lower || b > upper) {
            cp = bytesNeeded = bytesSeen = 0;
            this.state.AddOne(b);
            if (this.errorThrow) {
 throw new InvalidOperationException("Invalid UTF-8");
} else {
 return 0xfffd;
}
          }
          lower = 0x80;
          upper = 0xbf;
          ++bytesSeen;
          cp += (b - 0x80) << (6 * (bytesNeeded - bytesSeen));
          if (bytesSeen != bytesNeeded) {
            continue;
          }
          int ret = cp;
          cp = 0;
          bytesSeen = 0;
          bytesNeeded = 0;
          return ret;
        }
      }

      public int Read(int[] chars, int index, int length) {
        var count = 0;
        for (int i = 0; i < length; ++i) {
          int c = this.ReadChar();
          if (c < 0) {
            return count;
          }
          chars[index + i] = c;
          ++count;
        }
        return count;
      }
    }

    private sealed class WrappedStream : IByteReader {
      private readonly Stream stream;

      public WrappedStream(Stream stream) {
        this.stream = stream;
      }

      public int ReadByte() {
        try {
          return this.stream.ReadByte();
        } catch (IOException ex) {
          throw new InvalidOperationException(ex.Message, ex);
        }
      }
    }
  }
}
