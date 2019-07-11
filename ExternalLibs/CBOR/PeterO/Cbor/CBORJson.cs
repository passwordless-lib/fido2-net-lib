/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using System.Collections.Generic;
using System.Text;
using PeterO;
using PeterO.Numbers;

namespace PeterO.Cbor {
  internal sealed class CBORJson {
    // JSON parsing methods
    private static int SkipWhitespaceJSON(CharacterInputWithCount reader) {
      while (true) {
        int c = reader.ReadChar();
        if (c == -1 || (c != 0x20 && c != 0x0a && c != 0x0d && c != 0x09)) {
          return c;
        }
      }
    }

    private CharacterInputWithCount reader;
    private StringBuilder sb;

    private string NextJSONString() {
      int c;
      this.sb = this.sb ?? new StringBuilder();
      this.sb.Remove(0, this.sb.Length);
      while (true) {
        c = this.reader.ReadChar();
        if (c == -1 || c < 0x20) {
          this.reader.RaiseError("Unterminated string");
        }
        switch (c) {
          case '\\':
            c = this.reader.ReadChar();
            switch (c) {
              case '\\':
                this.sb.Append('\\');
                break;
              case '/':
                // Now allowed to be escaped under RFC 8259
                this.sb.Append('/');
                break;
              case '\"':
                this.sb.Append('\"');
                break;
              case 'b':
                this.sb.Append('\b');
                break;
              case 'f':
                this.sb.Append('\f');
                break;
              case 'n':
                this.sb.Append('\n');
                break;
              case 'r':
                this.sb.Append('\r');
                break;
              case 't':
                this.sb.Append('\t');
                break;
                case 'u': {  // Unicode escape
                  c = 0;
                  // Consists of 4 hex digits
                  for (var i = 0; i < 4; ++i) {
                    int ch = this.reader.ReadChar();
                    if (ch >= '0' && ch <= '9') {
                    c <<= 4;
                    c |= ch - '0';
                    } else if (ch >= 'A' && ch <= 'F') {
                    c <<= 4;
                    c |= ch + 10 - 'A';
                    } else if (ch >= 'a' && ch <= 'f') {
                    c <<= 4;
                    c |= ch + 10 - 'a';
                    } else {
                this.reader.RaiseError("Invalid Unicode escaped character");
                    }
                  }
                  if ((c & 0xf800) != 0xd800) {
                    // Non-surrogate
                    this.sb.Append((char)c);
                  } else if ((c & 0xfc00) == 0xd800) {
                    int ch = this.reader.ReadChar();
                    if (ch != '\\' || this.reader.ReadChar() != 'u') {
                    this.reader.RaiseError("Invalid escaped character");
                    }
                    var c2 = 0;
                    for (var i = 0; i < 4; ++i) {
                    ch = this.reader.ReadChar();
                    if (ch >= '0' && ch <= '9') {
                    c2 <<= 4;
                    c2 |= ch - '0';
                    } else if (ch >= 'A' && ch <= 'F') {
                    c2 <<= 4;
                    c2 |= ch + 10 - 'A';
                    } else if (ch >= 'a' && ch <= 'f') {
                    c2 <<= 4;
                    c2 |= ch + 10 - 'a';
                    } else {
                    this.reader.RaiseError("Invalid Unicode escaped character");
                    }
                    }
                    if ((c2 & 0xfc00) != 0xdc00) {
                    this.reader.RaiseError("Unpaired surrogate code point");
                    } else {
                    this.sb.Append((char)c);
                    this.sb.Append((char)c2);
                    }
                  } else {
                    this.reader.RaiseError("Unpaired surrogate code point");
                  }
                  break;
                }
              default:
                {
                  this.reader.RaiseError("Invalid escaped character");
                  break;
                }
            }
            break;
          case 0x22:  // double quote
            return this.sb.ToString();
          default: {
              // NOTE: Assumes the character reader
              // throws an error on finding illegal surrogate
              // pairs in the string or invalid encoding
              // in the stream
              if ((c >> 16) == 0) {
                this.sb.Append((char)c);
              } else {
              this.sb.Append((char)((((c - 0x10000) >> 10) & 0x3ff) +
                  0xd800));
                this.sb.Append((char)(((c - 0x10000) & 0x3ff) + 0xdc00));
              }
              break;
            }
        }
      }
    }

    private CBORObject NextJSONValue(
      int firstChar,
      int[] nextChar,
      int depth) {
      string str;
      int c = firstChar;
      CBORObject obj = null;
      if (c < 0) {
        this.reader.RaiseError("Unexpected end of data");
      }
      switch (c) {
        case '"':
          {
            // Parse a string
            // The tokenizer already checked the string for invalid
            // surrogate pairs, so just call the CBORObject
            // constructor directly
            obj = CBORObject.FromRaw(this.NextJSONString());
            nextChar[0] = SkipWhitespaceJSON(this.reader);
            return obj;
          }
        case '{':
          {
            // Parse an object
            obj = this.ParseJSONObject(depth + 1);
            nextChar[0] = SkipWhitespaceJSON(this.reader);
            return obj;
          }
        case '[':
          {
            // Parse an array
            obj = this.ParseJSONArray(depth + 1);
            nextChar[0] = SkipWhitespaceJSON(this.reader);
            return obj;
          }
        case 't':
          {
            // Parse true
          if (this.reader.ReadChar() != 'r' || this.reader.ReadChar() != 'u' ||
              this.reader.ReadChar() != 'e') {
              this.reader.RaiseError("Value can't be parsed.");
            }
            nextChar[0] = SkipWhitespaceJSON(this.reader);
            return CBORObject.True;
          }
        case 'f':
          {
            // Parse false
          if (this.reader.ReadChar() != 'a' || this.reader.ReadChar() != 'l' ||
              this.reader.ReadChar() != 's' || this.reader.ReadChar() != 'e') {
              this.reader.RaiseError("Value can't be parsed.");
            }
            nextChar[0] = SkipWhitespaceJSON(this.reader);
            return CBORObject.False;
          }
        case 'n':
          {
            // Parse null
          if (this.reader.ReadChar() != 'u' || this.reader.ReadChar() != 'l' ||
              this.reader.ReadChar() != 'l') {
              this.reader.RaiseError("Value can't be parsed.");
            }
            nextChar[0] = SkipWhitespaceJSON(this.reader);
            return CBORObject.Null;
          }
        case '-':
          {
            // Parse a negative number
            var lengthTwo = true;
            c = this.reader.ReadChar();
            if (c < '0' || c > '9') {
              this.reader.RaiseError("JSON number can't be parsed.");
            }
            int cval = -(c - '0');
            int cstart = c;
            StringBuilder sb = null;
            c = this.reader.ReadChar();
            while (c == '-' || c == '+' || c == '.' || (c >= '0' && c <= '9') ||
                   c == 'e' || c == 'E') {
              if (lengthTwo) {
                sb = new StringBuilder();
                sb.Append((char)'-');
                sb.Append((char)cstart);
                lengthTwo = false;
              }
              sb.Append((char)c);
              c = this.reader.ReadChar();
            }
            if (lengthTwo) {
              obj = cval == 0 ?
              CBORDataUtilities.ParseJSONNumber("-0", true, false, true) :
                CBORObject.FromObject(cval);
            } else {
              str = sb.ToString();
              obj = CBORDataUtilities.ParseJSONNumber(str);
              if (obj == null) {
                this.reader.RaiseError("JSON number can't be parsed. " + str);
              }
            }
            if (c == -1 || (c != 0x20 && c != 0x0a && c != 0x0d && c != 0x09)) {
              nextChar[0] = c;
            } else {
              nextChar[0] = SkipWhitespaceJSON(this.reader);
            }
            return obj;
          }
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
          {
            // Parse a number
            var lengthOne = true;
            int cval = c - '0';
            int cstart = c;
            StringBuilder sb = null;
            c = this.reader.ReadChar();
            while (c == '-' || c == '+' || c == '.' || (c >= '0' && c <= '9') ||
                   c == 'e' || c == 'E') {
              if (lengthOne) {
                sb = new StringBuilder();
                sb.Append((char)cstart);
                lengthOne = false;
              }
              sb.Append((char)c);
              c = this.reader.ReadChar();
            }
            if (lengthOne) {
              obj = CBORObject.FromObject(cval);
            } else {
              str = sb.ToString();
              obj = CBORDataUtilities.ParseJSONNumber(str);
              if (obj == null) {
                this.reader.RaiseError("JSON number can't be parsed. " + str);
              }
            }
            if (c == -1 || (c != 0x20 && c != 0x0a && c != 0x0d && c != 0x09)) {
              nextChar[0] = c;
            } else {
              nextChar[0] = SkipWhitespaceJSON(this.reader);
            }
            return obj;
          }
        default:
          this.reader.RaiseError("Value can't be parsed.");
          break;
      }
      return null;
    }

    private bool noDuplicates;

    public CBORJson(CharacterInputWithCount reader, bool noDuplicates) {
      this.reader = reader;
      this.sb = null;
      this.noDuplicates = noDuplicates;
    }

    public CBORObject ParseJSON(bool objectOrArrayOnly, int[] nextchar) {
      int c;
      CBORObject ret;
      c = SkipWhitespaceJSON(this.reader);
      if (c == '[') {
        ret = this.ParseJSONArray(0);
        nextchar[0] = SkipWhitespaceJSON(this.reader);
        return ret;
      }
      if (c == '{') {
        ret = this.ParseJSONObject(0);
        nextchar[0] = SkipWhitespaceJSON(this.reader);
        return ret;
      }
      if (objectOrArrayOnly) {
        this.reader.RaiseError("A JSON object must begin with '{' or '['");
      }
      return this.NextJSONValue(c, nextchar, 0);
    }

    internal static CBORObject ParseJSONValue(
      CharacterInputWithCount reader,
      bool noDuplicates,
      bool objectOrArrayOnly,
      int[] nextchar) {
      var cj = new CBORJson(reader, noDuplicates);
      return cj.ParseJSON(objectOrArrayOnly, nextchar);
    }

    private CBORObject ParseJSONObject(int depth) {
      // Assumes that the last character read was '{'
      if (depth > 1000) {
        this.reader.RaiseError("Too deeply nested");
      }
      int c;
      CBORObject key = null;
      CBORObject obj;
      var nextchar = new int[1];
      var seenComma = false;
      var myHashMap = new Dictionary<CBORObject, CBORObject>();
      while (true) {
        c = SkipWhitespaceJSON(this.reader);
        switch (c) {
          case -1:
            this.reader.RaiseError("A JSONObject must end with '}'");
            break;
          case '}':
            if (seenComma) {
              // Situation like '{"0"=>1,}'
              this.reader.RaiseError("Trailing comma");
              return null;
            }
            return CBORObject.FromRaw(myHashMap);
            default: {
              // Read the next string
              if (c < 0) {
                this.reader.RaiseError("Unexpected end of data");
                return null;
              }
              if (c != '"') {
                this.reader.RaiseError("Expected a string as a key");
                return null;
              }
              // Parse a string that represents the object's key
              // The tokenizer already checked the string for invalid
              // surrogate pairs, so just call the CBORObject
              // constructor directly
              obj = CBORObject.FromRaw(this.NextJSONString());
              key = obj;
              if (this.noDuplicates && myHashMap.ContainsKey(obj)) {
                this.reader.RaiseError("Key already exists: " + key);
                return null;
              }
              break;
            }
        }
        if (SkipWhitespaceJSON(this.reader) != ':') {
          this.reader.RaiseError("Expected a ':' after a key");
        }
        // NOTE: Will overwrite existing value
        myHashMap[key] = this.NextJSONValue(
          SkipWhitespaceJSON(this.reader),
          nextchar,
          depth);
        switch (nextchar[0]) {
          case ',':
            seenComma = true;
            break;
          case '}':
            return CBORObject.FromRaw(myHashMap);
            default: this.reader.RaiseError("Expected a ',' or '}'");
            break;
        }
      }
    }

    internal CBORObject ParseJSONArray(int depth) {
      // Assumes that the last character read was '['
      if (depth > 1000) {
        this.reader.RaiseError("Too deeply nested");
      }
      var myArrayList = new List<CBORObject>();
      var seenComma = false;
      var nextchar = new int[1];
      while (true) {
        int c = SkipWhitespaceJSON(this.reader);
        if (c == ']') {
          if (seenComma) {
            // Situation like '[0,1,]'
            this.reader.RaiseError("Trailing comma");
          }
          return CBORObject.FromRaw(myArrayList);
        }
        if (c == ',') {
          // Situation like '[,0,1,2]' or '[0,,1]'
          this.reader.RaiseError("Empty array element");
        }
        myArrayList.Add(
          this.NextJSONValue(
            c,
            nextchar,
            depth));
        c = nextchar[0];
        switch (c) {
          case ',':
            seenComma = true;
            break;
          case ']':
            return CBORObject.FromRaw(myArrayList);
          default:
            this.reader.RaiseError("Expected a ',' or ']'");
            break;
        }
      }
    }

    private const string Hex16 = "0123456789ABCDEF";

    internal static void WriteJSONStringUnquoted(
      string str,
      StringOutput sb) {
      // Surrogates were already verified when this
      // string was added to the CBOR object; that check
      // is not repeated here
      var first = true;
      for (var i = 0; i < str.Length; ++i) {
        char c = str[i];
        if (c == '\\' || c == '"') {
          if (first) {
            first = false;
            sb.WriteString(str, 0, i);
          }
          sb.WriteCodePoint((int)'\\');
          sb.WriteCodePoint((int)c);
        } else if (c < 0x20 || (c >= 0x7f && (c == 0x2028 || c == 0x2029 ||
                    (c >= 0x7f && c <= 0xa0) || c == 0xfeff || c == 0xfffe ||
                    c == 0xffff))) {
          // Control characters, and also the line and paragraph separators
          // which apparently can't appear in JavaScript (as opposed to
          // JSON) strings
          if (first) {
            first = false;
            sb.WriteString(str, 0, i);
          }
          if (c == 0x0d) {
            sb.WriteString("\\r");
          } else if (c == 0x0a) {
            sb.WriteString("\\n");
          } else if (c == 0x08) {
            sb.WriteString("\\b");
          } else if (c == 0x0c) {
            sb.WriteString("\\f");
          } else if (c == 0x09) {
            sb.WriteString("\\t");
          } else if (c == 0x85) {
            sb.WriteString("\\u0085");
          } else if (c >= 0x100) {
            sb.WriteString("\\u");
            sb.WriteCodePoint((int)Hex16[(int)((c >> 12) & 15)]);
            sb.WriteCodePoint((int)Hex16[(int)((c >> 8) & 15)]);
            sb.WriteCodePoint((int)Hex16[(int)((c >> 4) & 15)]);
            sb.WriteCodePoint((int)Hex16[(int)(c & 15)]);
          } else {
            sb.WriteString("\\u00");
            sb.WriteCodePoint((int)Hex16[(int)(c >> 4)]);
            sb.WriteCodePoint((int)Hex16[(int)(c & 15)]);
          }
        } else if (!first) {
          if ((c & 0xfc00) == 0xd800) {
            sb.WriteString(str, i, 2);
            ++i;
          } else {
            sb.WriteCodePoint((int)c);
          }
        }
      }
      if (first) {
        sb.WriteString(str);
      }
    }

    internal static void WriteJSONToInternal(
      CBORObject obj,
      StringOutput writer,
      JSONOptions options) {
      int type = obj.ItemType;
      object thisItem = obj.ThisItem;
      switch (type) {
          case CBORObject.CBORObjectTypeSimpleValue: {
            if (obj.IsTrue) {
              writer.WriteString("true");
              return;
            }
            if (obj.IsFalse) {
              writer.WriteString("false");
              return;
            }
            writer.WriteString("null");
            return;
          }
          case CBORObject.CBORObjectTypeSingle: {
            var f = (float)thisItem;
            if (Single.IsNegativeInfinity(f) ||
                Single.IsPositiveInfinity(f) || Single.IsNaN(f)) {
              writer.WriteString("null");
              return;
            }
            writer.WriteString(
              CBORObject.TrimDotZero(
                CBORUtilities.SingleToString(f)));
            return;
          }
          case CBORObject.CBORObjectTypeDouble: {
            var f = (double)thisItem;
            if (Double.IsNegativeInfinity(f) || Double.IsPositiveInfinity(f) ||
                Double.IsNaN(f)) {
              writer.WriteString("null");
              return;
            }
            string dblString = CBORUtilities.DoubleToString(f);
            writer.WriteString(
              CBORObject.TrimDotZero(dblString));
            return;
          }
          case CBORObject.CBORObjectTypeInteger: {
            var longItem = (long)thisItem;
            writer.WriteString(CBORUtilities.LongToString(longItem));
            return;
          }
          case CBORObject.CBORObjectTypeBigInteger: {
            writer.WriteString(((EInteger)thisItem).ToString());
            return;
          }
          case CBORObject.CBORObjectTypeExtendedDecimal: {
            var dec = (EDecimal)thisItem;
            if (dec.IsInfinity() || dec.IsNaN()) {
              writer.WriteString("null");
            } else {
              writer.WriteString(dec.ToString());
            }
            return;
          }
          case CBORObject.CBORObjectTypeExtendedFloat: {
            var flo = (EFloat)thisItem;
            if (flo.IsInfinity() || flo.IsNaN()) {
              writer.WriteString("null");
              return;
            }
            if (flo.IsFinite &&
                flo.Exponent.Abs().CompareTo((EInteger)2500) > 0) {
              // Too inefficient to convert to a decimal number
              // from a bigfloat with a very high exponent,
              // so convert to double instead
              double f = flo.ToDouble();
              if (Double.IsNegativeInfinity(f) ||
                  Double.IsPositiveInfinity(f) || Double.IsNaN(f)) {
                writer.WriteString("null");
                return;
              }
              string dblString =
                  CBORUtilities.DoubleToString(f);
              writer.WriteString(
                CBORObject.TrimDotZero(dblString));
              return;
            }
            writer.WriteString(flo.ToString());
            return;
          }
        case CBORObject.CBORObjectTypeByteString:
          {
            var byteArray = (byte[])thisItem;
            if (byteArray.Length == 0) {
              writer.WriteString("\"\"");
              return;
            }
            writer.WriteCodePoint((int)'\"');
            if (obj.HasTag(22)) {
              Base64.WriteBase64(
                writer,
                byteArray,
                0,
                byteArray.Length,
                options.Base64Padding);
            } else if (obj.HasTag(23)) {
              // Write as base16
              for (int i = 0; i < byteArray.Length; ++i) {
                writer.WriteCodePoint((int)Hex16[(byteArray[i] >> 4) & 15]);
                writer.WriteCodePoint((int)Hex16[byteArray[i] & 15]);
              }
            } else {
              Base64.WriteBase64URL(
                writer,
                byteArray,
                0,
                byteArray.Length,
                options.Base64Padding);
            }
            writer.WriteCodePoint((int)'\"');
            break;
          }
          case CBORObject.CBORObjectTypeTextString: {
            var thisString = (string)thisItem;
            if (thisString.Length == 0) {
              writer.WriteString("\"\"");
              return;
            }
            writer.WriteCodePoint((int)'\"');
            WriteJSONStringUnquoted(thisString, writer);
            writer.WriteCodePoint((int)'\"');
            break;
          }
          case CBORObject.CBORObjectTypeArray: {
            var first = true;
            writer.WriteCodePoint((int)'[');
            foreach (CBORObject i in obj.AsList()) {
              if (!first) {
                writer.WriteCodePoint((int)',');
              }
              WriteJSONToInternal(i, writer, options);
              first = false;
            }
            writer.WriteCodePoint((int)']');
            break;
          }
          case CBORObject.CBORObjectTypeExtendedRational: {
            var dec = (ERational)thisItem;
            EDecimal f = dec.ToEDecimalExactIfPossible(
              EContext.Decimal128.WithUnlimitedExponents());
            if (!f.IsFinite) {
              writer.WriteString("null");
            } else {
              writer.WriteString(f.ToString());
            }
            break;
          }
          case CBORObject.CBORObjectTypeMap: {
            var first = true;
            var hasNonStringKeys = false;
            IDictionary<CBORObject, CBORObject> objMap = obj.AsMap();
            foreach (KeyValuePair<CBORObject, CBORObject> entry in objMap) {
              CBORObject key = entry.Key;
              if (key.ItemType != CBORObject.CBORObjectTypeTextString) {
                hasNonStringKeys = true;
                break;
              }
            }
            if (!hasNonStringKeys) {
              writer.WriteCodePoint((int)'{');
              foreach (KeyValuePair<CBORObject, CBORObject> entry in objMap) {
                CBORObject key = entry.Key;
                CBORObject value = entry.Value;
                if (!first) {
                  writer.WriteCodePoint((int)',');
                }
                writer.WriteCodePoint((int)'\"');
                WriteJSONStringUnquoted((string)key.ThisItem, writer);
                writer.WriteCodePoint((int)'\"');
                writer.WriteCodePoint((int)':');
                WriteJSONToInternal(value, writer, options);
                first = false;
              }
              writer.WriteCodePoint((int)'}');
            } else {
              // This map has non-string keys
              IDictionary<string, CBORObject> stringMap = new
                Dictionary<string, CBORObject>();
              // Copy to a map with String keys, since
              // some keys could be duplicates
              // when serialized to strings
              foreach (KeyValuePair<CBORObject, CBORObject> entry in objMap) {
                CBORObject key = entry.Key;
                CBORObject value = entry.Value;
           string str = (key.ItemType == CBORObject.CBORObjectTypeTextString) ?
                  ((string)key.ThisItem) : key.ToJSONString();
                stringMap[str] = value;
              }
              first = true;
              writer.WriteCodePoint((int)'{');
              foreach (KeyValuePair<string, CBORObject> entry in stringMap) {
                string key = entry.Key;
                CBORObject value = entry.Value;
                if (!first) {
                  writer.WriteCodePoint((int)',');
                }
                writer.WriteCodePoint((int)'\"');
                WriteJSONStringUnquoted((string)key, writer);
                writer.WriteCodePoint((int)'\"');
                writer.WriteCodePoint((int)':');
                WriteJSONToInternal(value, writer, options);
                first = false;
              }
              writer.WriteCodePoint((int)'}');
            }
            break;
          }
        default: throw new InvalidOperationException("Unexpected item type");
      }
    }
  }
}
