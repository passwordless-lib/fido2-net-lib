/*
Written by Peter O. in 2013.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using System.IO;
using PeterO.Numbers;

namespace PeterO.Cbor {
  // Contains extra methods placed separately
  // because they are not CLS-compliant or they
  // are specific to the .NET framework.
  public sealed partial class CBORObject {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsUInt16"]/*'/>
    [CLSCompliant(false)]
    public ushort AsUInt16() {
      int v = this.AsInt32();
      if (v > UInt16.MaxValue || v < 0) {
        throw new OverflowException("This object's value is out of range");
      }
      return (ushort)v;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsUInt32"]/*'/>
    [CLSCompliant(false)]
    public uint AsUInt32() {
      ulong v = this.AsUInt64();
      if (v > UInt32.MaxValue) {
        throw new OverflowException("This object's value is out of range");
      }
      return (uint)v;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsSByte"]/*'/>
    [CLSCompliant(false)]
    public sbyte AsSByte() {
      int v = this.AsInt32();
      if (v > SByte.MaxValue || v < SByte.MinValue) {
        throw new OverflowException("This object's value is out of range");
      }
      return (sbyte)v;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.WriteValue(System.IO.Stream,System.Int32,System.UInt32)"]/*'/>
    [CLSCompliant(false)]
  public static int WriteValue(
  Stream outputStream,
  int majorType,
  uint value) {
   if (outputStream == null) {
  throw new ArgumentNullException(nameof(outputStream));
}
      return WriteValue(outputStream, majorType, (long)value);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.WriteValue(System.IO.Stream,System.Int32,System.UInt64)"]/*'/>
    [CLSCompliant(false)]
 public static int WriteValue(
  Stream outputStream,
  int majorType,
  ulong value) {
   if (outputStream == null) {
  throw new ArgumentNullException(nameof(outputStream));
}
      if (value <= Int64.MaxValue) {
        return WriteValue(outputStream, majorType, (long)value);
      } else {
        if (majorType < 0) {
  throw new ArgumentException("majorType (" + majorType +
    ") is less than 0");
}
if (majorType > 7) {
  throw new ArgumentException("majorType (" + majorType +
    ") is more than 7");
}
        if (majorType == 7) {
   throw new ArgumentException("majorType is 7 and value is greater than 255");
        }
        byte[] bytes = { (byte)(27 | (majorType << 5)), (byte)((value >>
          56) & 0xff),
        (byte)((value >> 48) & 0xff), (byte)((value >> 40) & 0xff),
        (byte)((value >> 32) & 0xff), (byte)((value >> 24) & 0xff),
        (byte)((value >> 16) & 0xff), (byte)((value >> 8) & 0xff),
        (byte)(value & 0xff) };
        outputStream.Write(bytes, 0, bytes.Length);
        return bytes.Length;
      }
    }

    private static EInteger DecimalToEInteger(decimal dec) {
      return ((EDecimal)dec).ToEInteger();
    }

    private static decimal ExtendedRationalToDecimal(ERational
      extendedNumber) {
      return (decimal)extendedNumber;
    }

    private static decimal ExtendedDecimalToDecimal(EDecimal
      extendedNumber) {
 return (decimal)extendedNumber;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsDecimal"]/*'/>
    [CLSCompliant(false)]
    public decimal AsDecimal() {
      return (this.ItemType == CBORObjectTypeInteger) ?
        ((decimal)(long)this.ThisItem) : ((this.ItemType ==
        CBORObjectTypeExtendedRational) ?
        ExtendedRationalToDecimal((ERational)this.ThisItem) :
        ExtendedDecimalToDecimal(this.AsEDecimal()));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsUInt64"]/*'/>
    [CLSCompliant(false)]
    public ulong AsUInt64() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("Not a number type");
      }
      EInteger bigint = cn.AsEInteger(this.ThisItem);
      if (bigint.Sign < 0 || bigint.GetSignedBitLength() > 64) {
        throw new OverflowException("This object's value is out of range");
      }
             return (ulong)bigint;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.SByte,System.IO.Stream)"]/*'/>
    [CLSCompliant(false)]
    public static void Write(sbyte value, Stream stream) {
      Write((long)value, stream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.UInt64,System.IO.Stream)"]/*'/>
    [CLSCompliant(false)]
    public static void Write(ulong value, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (value <= Int64.MaxValue) {
        Write((long)value, stream);
      } else {
        stream.WriteByte((byte)27);
        stream.WriteByte((byte)((value >> 56) & 0xff));
        stream.WriteByte((byte)((value >> 48) & 0xff));
        stream.WriteByte((byte)((value >> 40) & 0xff));
        stream.WriteByte((byte)((value >> 32) & 0xff));
        stream.WriteByte((byte)((value >> 24) & 0xff));
        stream.WriteByte((byte)((value >> 16) & 0xff));
        stream.WriteByte((byte)((value >> 8) & 0xff));
        stream.WriteByte((byte)(value & 0xff));
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Decimal)"]/*'/>
    public static CBORObject FromObject(decimal value) {
      return FromObject((EDecimal)value);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.UInt32,System.IO.Stream)"]/*'/>
    [CLSCompliant(false)]
    public static void Write(uint value, Stream stream) {
      Write((ulong)value, stream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.UInt16,System.IO.Stream)"]/*'/>
    [CLSCompliant(false)]
    public static void Write(ushort value, Stream stream) {
      Write((ulong)value, stream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.SByte)"]/*'/>
    [CLSCompliant(false)]
    public static CBORObject FromObject(sbyte value) {
      return FromObject((long)value);
    }

    private static EInteger UInt64ToEInteger(ulong value) {
      var data = new byte[9];
      ulong uvalue = value;
      data[0] = (byte)(uvalue & 0xff);
      data[1] = (byte)((uvalue >> 8) & 0xff);
      data[2] = (byte)((uvalue >> 16) & 0xff);
      data[3] = (byte)((uvalue >> 24) & 0xff);
      data[4] = (byte)((uvalue >> 32) & 0xff);
      data[5] = (byte)((uvalue >> 40) & 0xff);
      data[6] = (byte)((uvalue >> 48) & 0xff);
      data[7] = (byte)((uvalue >> 56) & 0xff);
      data[8] = (byte)0;
      return EInteger.FromBytes(data, true);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.UInt64)"]/*'/>
    [CLSCompliant(false)]
    public static CBORObject FromObject(ulong value) {
      return CBORObject.FromObject(UInt64ToEInteger(value));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.UInt32)"]/*'/>
    [CLSCompliant(false)]
    public static CBORObject FromObject(uint value) {
      return FromObject((long)(Int64)value);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.UInt16)"]/*'/>
    [CLSCompliant(false)]
    public static CBORObject FromObject(ushort value) {
      return FromObject((long)(Int64)value);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObjectAndTag(System.Object,System.UInt64)"]/*'/>
    [CLSCompliant(false)]
    public static CBORObject FromObjectAndTag(Object o, ulong tag) {
      return FromObjectAndTag(o, UInt64ToEInteger(tag));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToObject``1"]/*'/>
    public T ToObject<T>() {
      return (T)this.ToObject(typeof(T));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToObject``1(CBORTypeMapper)"]/*'/>
    public T ToObject<T>(CBORTypeMapper mapper) {
      return (T)this.ToObject(typeof(T), mapper);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToObject``1(PODOptions)"]/*'/>
    public T ToObject<T>(PODOptions options) {
      return (T)this.ToObject(typeof(T), options);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToObject``1(CBORTypeMapper,PODOptions)"]/*'/>
    public T ToObject<T>(CBORTypeMapper mapper, PODOptions options) {
      return (T)this.ToObject(typeof(T), mapper, options);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.op_Addition(CBORObject,CBORObject)"]/*'/>
    public static CBORObject operator +(CBORObject a, CBORObject b) {
      return Addition(a, b);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.op_Subtraction(CBORObject,CBORObject)"]/*'/>
    public static CBORObject operator -(CBORObject a, CBORObject b) {
      return Subtract(a, b);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.op_Multiply(CBORObject,CBORObject)"]/*'/>
    public static CBORObject operator *(CBORObject a, CBORObject b) {
      return Multiply(a, b);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.op_Division(CBORObject,CBORObject)"]/*'/>
    public static CBORObject operator /(CBORObject a, CBORObject b) {
      return Divide(a, b);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.op_Modulus(CBORObject,CBORObject)"]/*'/>
    public static CBORObject operator %(CBORObject a, CBORObject b) {
      return Remainder(a, b);
    }
  }
}
