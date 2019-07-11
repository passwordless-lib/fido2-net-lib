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
#pragma warning disable 618

namespace PeterO.Cbor {
  internal class CBORReader {
    private readonly Stream stream;
    private int depth;
    private CBORDuplicatePolicy policy;
    private StringRefs stringRefs;
    private bool hasSharableObjects;

    public CBORReader(Stream inStream) {
      this.stream = inStream;
      this.policy = CBORDuplicatePolicy.Overwrite;
    }

    internal enum CBORDuplicatePolicy {
      Overwrite, Disallow
    }

    public CBORDuplicatePolicy DuplicatePolicy {
      get {
        return this.policy;
      }

      set {
        this.policy = value;
      }
    }

    public CBORObject ResolveSharedRefsIfNeeded(CBORObject obj) {
      if (this.hasSharableObjects) {
        var sharedRefs = new SharedRefs();
        return ResolveSharedRefs(obj, sharedRefs);
      }
      return obj;
    }

    private static CBORObject ResolveSharedRefs(
  CBORObject obj,
  SharedRefs sharedRefs) {
  int type = obj.ItemType;
  bool hasTag = obj.MostOuterTag.Equals((EInteger)29);
  if (hasTag) {
    return sharedRefs.GetObject(obj.AsEInteger());
  }
  hasTag = obj.MostOuterTag.Equals((EInteger)28);
  if (hasTag) {
      obj = obj.Untag();
      sharedRefs.AddObject(obj);
  }
  if (type == CBORObject.CBORObjectTypeMap) {
    foreach (CBORObject key in obj.Keys) {
      CBORObject value = obj[key];
      CBORObject newvalue = ResolveSharedRefs(value, sharedRefs);
      if (value != newvalue) {
        obj[key] = newvalue;
      }
    }
  } else if (type == CBORObject.CBORObjectTypeArray) {
    for (var i = 0; i < obj.Count; ++i) {
      obj[i] = ResolveSharedRefs(obj[i], sharedRefs);
    }
  }
  return obj;
    }

    public CBORObject Read(CBORTypeFilter filter) {
      if (this.depth > 500) {
        throw new CBORException("Too deeply nested");
      }
      int firstbyte = this.stream.ReadByte();
      if (firstbyte < 0) {
        throw new CBORException("Premature end of data");
      }
      return this.ReadForFirstByte(firstbyte, filter);
    }

    public CBORObject ReadForFirstByte(
  int firstbyte,
  CBORTypeFilter filter) {
      if (this.depth > 500) {
        throw new CBORException("Too deeply nested");
      }
      if (firstbyte < 0) {
        throw new CBORException("Premature end of data");
      }
      if (firstbyte == 0xff) {
        throw new CBORException("Unexpected break code encountered");
      }
      int type = (firstbyte >> 5) & 0x07;
      int additional = firstbyte & 0x1f;
      int expectedLength = CBORObject.GetExpectedLength(firstbyte);
      // Data checks
      if (expectedLength == -1) {
        // if the head byte is invalid
        throw new CBORException("Unexpected data encountered");
      }
      if (filter != null) {
        // Check for valid major types if asked
        if (!filter.MajorTypeMatches(type)) {
          throw new CBORException("Unexpected data type encountered");
        }
        if (firstbyte >= 0xe0 && firstbyte <= 0xff && firstbyte != 0xf9 &&
        firstbyte != 0xfa && firstbyte != 0xfb) {
          if (!filter.NonFPSimpleValueAllowed()) {
            throw new CBORException("Unexpected data type encountered");
          }
        }
      }
      // Check if this represents a fixed object
      CBORObject fixedObject = CBORObject.GetFixedObject(firstbyte);
      if (fixedObject != null) {
        return fixedObject;
      }
      // Read fixed-length data
      byte[] data = null;
      if (expectedLength != 0) {
        data = new byte[expectedLength];
        // include the first byte because GetFixedLengthObject
        // will assume it exists for some head bytes
        data[0] = unchecked((byte)firstbyte);
        if (expectedLength > 1 &&
            this.stream.Read(data, 1, expectedLength - 1) != expectedLength
            - 1) {
          throw new CBORException("Premature end of data");
        }
        CBORObject cbor = CBORObject.GetFixedLengthObject(firstbyte, data);
        if (this.stringRefs != null && (type == 2 || type == 3)) {
          this.stringRefs.AddStringIfNeeded(cbor, expectedLength - 1);
        }
        return cbor;
      }
      var uadditional = (long)additional;
      EInteger bigintAdditional = EInteger.Zero;
      var hasBigAdditional = false;
      data = new byte[8];
      var lowAdditional = 0;
      switch (firstbyte & 0x1f) {
        case 24: {
            int tmp = this.stream.ReadByte();
            if (tmp < 0) {
              throw new CBORException("Premature end of data");
            }
            lowAdditional = tmp;
            uadditional = lowAdditional;
            break;
          }
        case 25: {
            if (this.stream.Read(data, 0, 2) != 2) {
              throw new CBORException("Premature end of data");
            }
            lowAdditional = ((int)(data[0] & (int)0xff)) << 8;
            lowAdditional |= (int)(data[1] & (int)0xff);
            uadditional = lowAdditional;
            break;
          }
        case 26: {
            if (this.stream.Read(data, 0, 4) != 4) {
              throw new CBORException("Premature end of data");
            }
            uadditional = ((long)(data[0] & (long)0xff)) << 24;
            uadditional |= ((long)(data[1] & (long)0xff)) << 16;
            uadditional |= ((long)(data[2] & (long)0xff)) << 8;
            uadditional |= (long)(data[3] & (long)0xff);
            break;
          }
        case 27: {
            if (this.stream.Read(data, 0, 8) != 8) {
              throw new CBORException("Premature end of data");
            }
            if ((((int)data[0]) & 0x80) != 0) {
              // Won't fit in a signed 64-bit number
              var uabytes = new byte[9];
              uabytes[0] = data[7];
              uabytes[1] = data[6];
              uabytes[2] = data[5];
              uabytes[3] = data[4];
              uabytes[4] = data[3];
              uabytes[5] = data[2];
              uabytes[6] = data[1];
              uabytes[7] = data[0];
              uabytes[8] = 0;
              hasBigAdditional = true;
              bigintAdditional = EInteger.FromBytes(uabytes, true);
            } else {
              uadditional = ((long)(data[0] & (long)0xff)) << 56;
              uadditional |= ((long)(data[1] & (long)0xff)) << 48;
              uadditional |= ((long)(data[2] & (long)0xff)) << 40;
              uadditional |= ((long)(data[3] & (long)0xff)) << 32;
              uadditional |= ((long)(data[4] & (long)0xff)) << 24;
              uadditional |= ((long)(data[5] & (long)0xff)) << 16;
              uadditional |= ((long)(data[6] & (long)0xff)) << 8;
              uadditional |= (long)(data[7] & (long)0xff);
            }
            break;
          }
      }
      // The following doesn't check for major types 0 and 1,
      // since all of them are fixed-length types and are
      // handled in the call to GetFixedLengthObject.
      if (type == 2) {  // Byte string
        if (additional == 31) {
          // Streaming byte string
          using (var ms = new MemoryStream()) {
            // Requires same type as this one
            while (true) {
              int nextByte = this.stream.ReadByte();
              if (nextByte == 0xff) {
                // break if the "break" code was read
                break;
              }
              long len = ReadDataLength(this.stream, nextByte, 2);
              if ((len >> 63) != 0 || len > Int32.MaxValue) {
                throw new CBORException("Length" + ToUnsignedBigInteger(len) +
                  " is bigger than supported ");
              }
              if (nextByte != 0x40) {
  // NOTE: 0x40 means the empty byte string
                ReadByteData(this.stream, len, ms);
              }
            }
            if (ms.Position > Int32.MaxValue) {
              throw new
  CBORException("Length of bytes to be streamed is bigger than supported ");
            }
            data = ms.ToArray();
            return new CBORObject(
  CBORObject.CBORObjectTypeByteString,
  data);
          }
        } else {
          if (hasBigAdditional) {
            throw new CBORException("Length of " +
                    bigintAdditional.ToString() + " is bigger than supported");
          }
          if (uadditional > Int32.MaxValue) {
            throw new CBORException("Length of " +
              CBORUtilities.LongToString(uadditional) +
              " is bigger than supported");
          }
          data = ReadByteData(this.stream, uadditional, null);
          var cbor = new CBORObject(CBORObject.CBORObjectTypeByteString, data);
          if (this.stringRefs != null) {
            int hint = (uadditional > Int32.MaxValue || hasBigAdditional) ?
            Int32.MaxValue : (int)uadditional;
            this.stringRefs.AddStringIfNeeded(cbor, hint);
          }
          return cbor;
        }
      }
      if (type == 3) {  // Text string
        if (additional == 31) {
          // Streaming text string
          var builder = new StringBuilder();
          while (true) {
            int nextByte = this.stream.ReadByte();
            if (nextByte == 0xff) {
              // break if the "break" code was read
              break;
            }
            long len = ReadDataLength(this.stream, nextByte, 3);
            if ((len >> 63) != 0 || len > Int32.MaxValue) {
              throw new CBORException("Length" + ToUnsignedBigInteger(len) +
                " is bigger than supported");
            }
            if (nextByte != 0x60) {
  // NOTE: 0x60 means the empty string
              if (PropertyMap.ExceedsKnownLength(this.stream, len)) {
                throw new CBORException("Premature end of data");
              }
              switch (
  DataUtilities.ReadUtf8(
  this.stream,
  (int)len,
  builder,
  false)) {
                case -1:
                  throw new CBORException("Invalid UTF-8");
                case -2:
                  throw new CBORException("Premature end of data");
              }
            }
          }
          return new CBORObject(
            CBORObject.CBORObjectTypeTextString,
            builder.ToString());
        } else {
          if (hasBigAdditional) {
            throw new CBORException("Length of " +
                    bigintAdditional.ToString() + " is bigger than supported");
          }
          if (uadditional > Int32.MaxValue) {
            throw new CBORException("Length of " +
              CBORUtilities.LongToString(uadditional) +
              " is bigger than supported");
          }
          if (PropertyMap.ExceedsKnownLength(this.stream, uadditional)) {
            throw new CBORException("Premature end of data");
          }
          var builder = new StringBuilder();
          switch (
  DataUtilities.ReadUtf8(
  this.stream,
  (int)uadditional,
  builder,
  false)) {
            case -1:
              throw new CBORException("Invalid UTF-8");
            case -2:
              throw new CBORException("Premature end of data");
          }
          var cbor = new CBORObject(
  CBORObject.CBORObjectTypeTextString,
  builder.ToString());
          if (this.stringRefs != null) {
            int hint = (uadditional > Int32.MaxValue || hasBigAdditional) ?
            Int32.MaxValue : (int)uadditional;
            this.stringRefs.AddStringIfNeeded(cbor, hint);
          }
          return cbor;
        }
      }
      if (type == 4) {  // Array
        CBORObject cbor = CBORObject.NewArray();
        if (additional == 31) {
          var vtindex = 0;
          // Indefinite-length array
          while (true) {
            int headByte = this.stream.ReadByte();
            if (headByte < 0) {
              throw new CBORException("Premature end of data");
            }
            if (headByte == 0xff) {
              // Break code was read
              break;
            }
            if (filter != null && !filter.ArrayIndexAllowed(vtindex)) {
              throw new CBORException("Array is too long");
            }
            ++this.depth;
            CBORObject o = this.ReadForFirstByte(
  headByte,
  filter == null ? null : filter.GetSubFilter(vtindex));
            --this.depth;
            cbor.Add(o);
            ++vtindex;
          }
          return cbor;
        }
        if (hasBigAdditional) {
          throw new CBORException("Length of " +
  bigintAdditional.ToString() + " is bigger than supported");
        }
        if (uadditional > Int32.MaxValue) {
          throw new CBORException("Length of " +
            CBORUtilities.LongToString(uadditional) +
            " is bigger than supported");
        }
        if (filter != null && !filter.ArrayLengthMatches(uadditional)) {
          throw new CBORException("Array is too long");
        }
        if (PropertyMap.ExceedsKnownLength(this.stream, uadditional)) {
          throw new CBORException("Remaining data too small for array length");
        }
        ++this.depth;
        for (long i = 0; i < uadditional; ++i) {
          cbor.Add(
            this.Read(filter == null ? null : filter.GetSubFilter(i)));
        }
        --this.depth;
        return cbor;
      }
      if (type == 5) {  // Map, type 5
        CBORObject cbor = CBORObject.NewMap();
        if (additional == 31) {
          // Indefinite-length map
          while (true) {
            int headByte = this.stream.ReadByte();
            if (headByte < 0) {
              throw new CBORException("Premature end of data");
            }
            if (headByte == 0xff) {
              // Break code was read
              break;
            }
            ++this.depth;
            CBORObject key = this.ReadForFirstByte(headByte, null);
            CBORObject value = this.Read(null);
            --this.depth;
            if (this.policy == CBORDuplicatePolicy.Disallow) {
              if (cbor.ContainsKey(key)) {
                throw new CBORException("Duplicate key already exists: " + key);
              }
            }
            cbor[key] = value;
          }
          return cbor;
        }
        if (hasBigAdditional) {
          throw new CBORException("Length of " +
  bigintAdditional.ToString() + " is bigger than supported");
        }
        if (uadditional > Int32.MaxValue) {
          throw new CBORException("Length of " +
            CBORUtilities.LongToString(uadditional) +
            " is bigger than supported");
        }
        if (PropertyMap.ExceedsKnownLength(this.stream, uadditional)) {
            throw new CBORException("Remaining data too small for map length");
        }
        for (long i = 0; i < uadditional; ++i) {
          ++this.depth;
          CBORObject key = this.Read(null);
          CBORObject value = this.Read(null);
          --this.depth;
          if (this.policy == CBORDuplicatePolicy.Disallow) {
            if (cbor.ContainsKey(key)) {
              throw new CBORException("Duplicate key already exists: " + key);
            }
          }
          cbor[key] = value;
        }
        return cbor;
      }
      if (type == 6) {  // Tagged item
        ICBORTag taginfo = null;
        var haveFirstByte = false;
        var newFirstByte = -1;
        if (!hasBigAdditional) {
          if (filter != null && !filter.TagAllowed(uadditional)) {
            throw new CBORException("Unexpected tag encountered: " +
                 uadditional);
          }
          int uad = uadditional >= 257 ? 257 : (uadditional < 0 ? 0 :
            (int)uadditional);
    switch (uad) {
            case 256:
              // Tag 256: String namespace
              this.stringRefs = this.stringRefs ?? (new StringRefs());
              this.stringRefs.Push();
              break;
            case 25:
              // String reference
              if (this.stringRefs == null) {
                throw new CBORException("No stringref namespace");
              }
              break;
     case 28:
     case 29:
          this.hasSharableObjects = true;
       break;
          }

          taginfo = CBORObject.FindTagConverterLong(uadditional);
        } else {
          if (filter != null && !filter.TagAllowed(bigintAdditional)) {
            throw new CBORException("Unexpected tag encountered: " +
                 uadditional);
          }
          #pragma warning disable 618

          taginfo = CBORObject.FindTagConverter(bigintAdditional);
        }
        ++this.depth;
        CBORObject o = haveFirstByte ? this.ReadForFirstByte(
  newFirstByte,
  taginfo == null ? null : taginfo.GetTypeFilter()) :
        this.Read(taginfo == null ? null : taginfo.GetTypeFilter());
        --this.depth;
        if (hasBigAdditional) {
          return CBORObject.FromObjectAndTag(o, bigintAdditional);
        }
        if (uadditional < 65536) {
          int uaddl = uadditional >= 257 ? 257 : (uadditional < 0 ? 0 :
            (int)uadditional);
          switch (uaddl) {
            case 256:
              // string tag
              this.stringRefs.Pop();
              break;
            case 25:
              // stringref tag
              return this.stringRefs.GetString(o.AsEInteger());
          }

          return CBORObject.FromObjectAndTag(
            o,
            (int)uadditional);
        }
        return CBORObject.FromObjectAndTag(
          o,
          (EInteger)uadditional);
      }
      throw new CBORException("Unexpected data encountered");
    }

    private static byte[] ReadByteData(
  Stream stream,
  long uadditional,
  Stream outputStream) {
      if ((uadditional >> 63) != 0 || uadditional > Int32.MaxValue) {
        throw new CBORException("Length" + ToUnsignedBigInteger(uadditional) +
          " is bigger than supported ");
      }
      if (PropertyMap.ExceedsKnownLength(stream, uadditional)) {
        throw new CBORException("Premature end of stream");
      }
      if (uadditional <= 0x10000) {
        // Simple case: small size
        var data = new byte[(int)uadditional];
        if (stream.Read(data, 0, data.Length) != data.Length) {
          throw new CBORException("Premature end of stream");
        }
        if (outputStream != null) {
          outputStream.Write(data, 0, data.Length);
          return null;
        }
        return data;
      } else {
        var tmpdata = new byte[0x10000];
        var total = (int)uadditional;
        if (outputStream != null) {
          while (total > 0) {
            int bufsize = Math.Min(tmpdata.Length, total);
            if (stream.Read(tmpdata, 0, bufsize) != bufsize) {
              throw new CBORException("Premature end of stream");
            }
            outputStream.Write(tmpdata, 0, bufsize);
            total -= bufsize;
          }
          return null;
        }
        using (var ms = new MemoryStream(0x10000)) {
          while (total > 0) {
            int bufsize = Math.Min(tmpdata.Length, total);
            if (stream.Read(tmpdata, 0, bufsize) != bufsize) {
              throw new CBORException("Premature end of stream");
            }
            ms.Write(tmpdata, 0, bufsize);
            total -= bufsize;
          }
          return ms.ToArray();
        }
      }
    }

    private static long ReadDataLength(
  Stream stream,
  int headByte,
  int expectedType) {
      if (headByte < 0) {
        throw new CBORException("Unexpected data encountered");
      }
      if (((headByte >> 5) & 0x07) != expectedType) {
        throw new CBORException("Unexpected data encountered");
      }
      headByte &= 0x1f;
      if (headByte < 24) {
        return headByte;
      }
      var data = new byte[8];
      switch (headByte & 0x1f) {
        case 24: {
            int tmp = stream.ReadByte();
            if (tmp < 0) {
              throw new CBORException("Premature end of data");
            }
            return tmp;
          }
        case 25: {
            if (stream.Read(data, 0, 2) != 2) {
              throw new CBORException("Premature end of data");
            }
            int lowAdditional = ((int)(data[0] & (int)0xff)) << 8;
            lowAdditional |= (int)(data[1] & (int)0xff);
            return lowAdditional;
          }
        case 26: {
            if (stream.Read(data, 0, 4) != 4) {
              throw new CBORException("Premature end of data");
            }
            long uadditional = ((long)(data[0] & (long)0xff)) << 24;
            uadditional |= ((long)(data[1] & (long)0xff)) << 16;
            uadditional |= ((long)(data[2] & (long)0xff)) << 8;
            uadditional |= (long)(data[3] & (long)0xff);
            return uadditional;
          }
        case 27: {
            if (stream.Read(data, 0, 8) != 8) {
              throw new CBORException("Premature end of data");
            }
            // Treat return value as an unsigned integer
            long uadditional = ((long)(data[0] & (long)0xff)) << 56;
            uadditional |= ((long)(data[1] & (long)0xff)) << 48;
            uadditional |= ((long)(data[2] & (long)0xff)) << 40;
            uadditional |= ((long)(data[3] & (long)0xff)) << 32;
            uadditional |= ((long)(data[4] & (long)0xff)) << 24;
            uadditional |= ((long)(data[5] & (long)0xff)) << 16;
            uadditional |= ((long)(data[6] & (long)0xff)) << 8;
            uadditional |= (long)(data[7] & (long)0xff);
            return uadditional;
          }
        case 28:
        case 29:
        case 30:
          throw new CBORException("Unexpected data encountered");
        case 31:
          throw new CBORException("Indefinite-length data not allowed here");
        default: return headByte;
      }
    }

    private static EInteger ToUnsignedBigInteger(long val) {
      var lval = (EInteger)(val & ~(1L << 63));
      if ((val >> 63) != 0) {
        EInteger bigintAdd = EInteger.One << 63;
        lval += (EInteger)bigintAdd;
      }
      return lval;
    }
  }
}
