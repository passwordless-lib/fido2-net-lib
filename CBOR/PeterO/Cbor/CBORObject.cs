/*
Written by Peter O. in 2013-2018.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PeterO;
using PeterO.Numbers;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:CBORObject"]/*'/>
  public sealed partial class CBORObject : IComparable<CBORObject>,
  IEquatable<CBORObject> {
    private static CBORObject ConstructSimpleValue(int v) {
      return new CBORObject(CBORObjectTypeSimpleValue, v);
    }

    private static CBORObject ConstructIntegerValue(int v) {
      return new CBORObject(CBORObjectTypeInteger, (long)v);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORObject.False"]/*'/>
#if CODE_ANALYSIS
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
      "Microsoft.Security",
      "CA2104",
      Justification = "This CBORObject is immutable")]
#endif

    public static readonly CBORObject False =
      CBORObject.ConstructSimpleValue(20);

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORObject.NaN"]/*'/>
    public static readonly CBORObject NaN = CBORObject.FromObject(Double.NaN);

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORObject.NegativeInfinity"]/*'/>
    public static readonly CBORObject NegativeInfinity =
      CBORObject.FromObject(Double.NegativeInfinity);

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORObject.Null"]/*'/>
#if CODE_ANALYSIS
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
      "Microsoft.Security",
      "CA2104",
      Justification = "This CBORObject is immutable")]
#endif

    public static readonly CBORObject Null =
      CBORObject.ConstructSimpleValue(22);

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORObject.PositiveInfinity"]/*'/>
    public static readonly CBORObject PositiveInfinity =
      CBORObject.FromObject(Double.PositiveInfinity);

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORObject.True"]/*'/>
#if CODE_ANALYSIS
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
      "Microsoft.Security",
      "CA2104",
      Justification = "This CBORObject is immutable")]
#endif

    public static readonly CBORObject True =
      CBORObject.ConstructSimpleValue(21);

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORObject.Undefined"]/*'/>
#if CODE_ANALYSIS
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
      "Microsoft.Security",
      "CA2104",
      Justification = "This CBORObject is immutable")]
#endif

    public static readonly CBORObject Undefined =
      CBORObject.ConstructSimpleValue(23);

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORObject.Zero"]/*'/>
    public static readonly CBORObject Zero =
      CBORObject.ConstructIntegerValue(0);

    internal const int CBORObjectTypeArray = 4;
    internal const int CBORObjectTypeBigInteger = 1;  // all other integers
    internal const int CBORObjectTypeByteString = 2;
    internal const int CBORObjectTypeDouble = 8;
    internal const int CBORObjectTypeExtendedDecimal = 9;
    internal const int CBORObjectTypeExtendedFloat = 11;
    internal const int CBORObjectTypeExtendedRational = 12;
    internal const int CBORObjectTypeInteger = 0;  // -(2^63).. (2^63-1)
    internal const int CBORObjectTypeMap = 5;
    internal const int CBORObjectTypeSimpleValue = 6;
    internal const int CBORObjectTypeSingle = 7;
    internal const int CBORObjectTypeTagged = 10;
    internal const int CBORObjectTypeTextString = 3;
    internal static readonly EInteger Int64MaxValue =
      (EInteger)Int64.MaxValue;

    internal static readonly EInteger Int64MinValue =
      (EInteger)Int64.MinValue;

    private const int StreamedStringBufferLength = 4096;

    private static readonly IDictionary<Object, ConverterInfo>
      ValueConverters = new Dictionary<Object, ConverterInfo>();

    private static readonly ICBORNumber[] NumberInterfaces = {
      new CBORInteger(), new CBOREInteger(), null, null,
      null, null, null, new CBORSingle(),
      new CBORDouble(), new CBORExtendedDecimal(),
      null, new CBORExtendedFloat(), new CBORExtendedRational()
    };

        #pragma warning disable 618
    private static readonly IDictionary<EInteger, ICBORTag>
      ValueTagHandlers = new Dictionary<EInteger, ICBORTag>();
        #pragma warning restore 618

    private static readonly EInteger UInt64MaxValue =
      (EInteger.One << 64) - EInteger.One;

    private static readonly EInteger[] ValueEmptyTags = new EInteger[0];
    // Expected lengths for each head byte.
    // 0 means length varies. -1 means invalid.
    private static readonly int[] ValueExpectedLengths = { 1, 1, 1, 1, 1, 1,
      1, 1, 1,
      1, 1, 1, 1, 1, 1, 1,  // major type 0
      1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 5, 9, -1, -1, -1, -1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // major type 1
      1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 5, 9, -1, -1, -1, -1,
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,  // major type 2
      17, 18, 19, 20, 21, 22, 23, 24, 0, 0, 0, 0, -1, -1, -1, 0,
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,  // major type 3
      17, 18, 19, 20, 21, 22, 23, 24, 0, 0, 0, 0, -1, -1, -1, 0,
      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // major type 4
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, -1, 0,
      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // major type 5
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, -1, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // major type 6
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, -1, -1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // major type 7
      1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 5, 9, -1, -1, -1, -1 };

    private static readonly byte[] ValueFalseBytes = { 0x66, 0x61, 0x6c,
      0x73, 0x65 };

    private static readonly byte[] ValueNullBytes = { 0x6e, 0x75, 0x6c, 0x6c };

    private static readonly int[] ValueNumberTypeOrder = { 0, 0, 2, 3, 4, 5,
      1, 0, 0,
      0, 0, 0, 0 };

    private static readonly byte[] ValueTrueBytes = { 0x74, 0x72, 0x75, 0x65 };

    private static CBORObject[] valueFixedObjects = InitializeFixedObjects();

    private readonly int itemtypeValue;
    private readonly object itemValue;
    private readonly int tagHigh;
    private readonly int tagLow;

    internal CBORObject(CBORObject obj, int tagLow, int tagHigh) {
      this.itemtypeValue = CBORObjectTypeTagged;
      this.itemValue = obj;
      this.tagLow = tagLow;
      this.tagHigh = tagHigh;
    }

    internal CBORObject(int type, object item) {
#if DEBUG
      // Check range in debug mode to ensure that Integer and EInteger
      // are unambiguous
      if ((type == CBORObjectTypeBigInteger) &&
          ((EInteger)item).CompareTo(Int64MinValue) >= 0 &&
          ((EInteger)item).CompareTo(Int64MaxValue) <= 0) {
        throw new ArgumentException("Big integer is within range for Integer");
      }
      if (type == CBORObjectTypeArray && !(item is IList<CBORObject>)) {
        throw new InvalidOperationException();
      }
#endif
      this.itemtypeValue = type;
      this.itemValue = item;
      this.tagLow = 0;
      this.tagHigh = 0;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.Count"]/*'/>
    public int Count {
      get {
        return (this.ItemType == CBORObjectTypeArray) ? this.AsList().Count :
          ((this.ItemType == CBORObjectTypeMap) ? this.AsMap().Count : 0);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.InnermostTag"]/*'/>
    [Obsolete("Use MostInnerTag instead.")]
    public BigInteger InnermostTag {
      get {
        EInteger ei = this.MostInnerTag;
        String eis = ei.ToString();
        return BigInteger.fromString(eis);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.OutermostTag"]/*'/>
    [Obsolete("Use MostOuterTag instead.")]
    public BigInteger OutermostTag {
      get {
        EInteger ei = this.MostOuterTag;
        return BigInteger.fromString(this.MostOuterTag.ToString());
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.MostInnerTag"]/*'/>
    public EInteger MostInnerTag {
      get {
        if (!this.IsTagged) {
          return EInteger.FromInt32(-1);
        }
        CBORObject previtem = this;
        var curitem = (CBORObject)this.itemValue;
        while (curitem.IsTagged) {
          previtem = curitem;
          curitem = (CBORObject)curitem.itemValue;
        }
        if (previtem.tagHigh == 0 && previtem.tagLow >= 0 &&
            previtem.tagLow < 0x10000) {
          return (EInteger)previtem.tagLow;
        }
        return LowHighToEInteger(
          previtem.tagLow,
          previtem.tagHigh);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.IsFalse"]/*'/>
    public bool IsFalse {
      get {
        return this.ItemType == CBORObjectTypeSimpleValue && (int)this.ThisItem
          == 20;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.IsFinite"]/*'/>
    public bool IsFinite {
      get {
        return this.Type == CBORType.Number && !this.IsInfinity() &&
          !this.IsNaN();
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.IsIntegral"]/*'/>
    public bool IsIntegral {
      get {
        ICBORNumber cn = NumberInterfaces[this.ItemType];
        return (cn != null) && cn.IsIntegral(this.ThisItem);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.IsNull"]/*'/>
    public bool IsNull {
      get {
        return this.ItemType == CBORObjectTypeSimpleValue && (int)this.ThisItem
          == 22;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.IsTagged"]/*'/>
    public bool IsTagged {
      get {
        return this.itemtypeValue == CBORObjectTypeTagged;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.IsTrue"]/*'/>
    public bool IsTrue {
      get {
        return this.ItemType == CBORObjectTypeSimpleValue && (int)this.ThisItem
          == 21;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.IsUndefined"]/*'/>
    public bool IsUndefined {
      get {
        return this.ItemType == CBORObjectTypeSimpleValue && (int)this.ThisItem
          == 23;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.IsZero"]/*'/>
    public bool IsZero {
      get {
        ICBORNumber cn = NumberInterfaces[this.ItemType];
        return cn != null && cn.IsZero(this.ThisItem);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.Keys"]/*'/>
    public ICollection<CBORObject> Keys {
      get {
        if (this.ItemType == CBORObjectTypeMap) {
          IDictionary<CBORObject, CBORObject> dict = this.AsMap();
          return dict.Keys;
        }
        throw new InvalidOperationException("Not a map");
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.IsNegative"]/*'/>
    public bool IsNegative {
      get {
        ICBORNumber cn = NumberInterfaces[this.ItemType];
        return (cn != null) && cn.IsNegative(this.ThisItem);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.MostOuterTag"]/*'/>
    public EInteger MostOuterTag {
      get {
        if (!this.IsTagged) {
          return EInteger.FromInt32(-1);
        }
        if (this.tagHigh == 0 &&
            this.tagLow >= 0 && this.tagLow < 0x10000) {
          return (EInteger)this.tagLow;
        }
        return LowHighToEInteger(
          this.tagLow,
          this.tagHigh);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.Sign"]/*'/>
    public int Sign {
      get {
        int ret = GetSignInternal(this.ItemType, this.ThisItem);
        if (ret == 2) {
          throw new InvalidOperationException("This object is not a number.");
        }
        return ret;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.SimpleValue"]/*'/>
    public int SimpleValue {
      get {
        return (this.ItemType == CBORObjectTypeSimpleValue) ?
          ((int)this.ThisItem) : (-1);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.Type"]/*'/>
    public CBORType Type {
      get {
        switch (this.ItemType) {
          case CBORObjectTypeInteger:
          case CBORObjectTypeBigInteger:
          case CBORObjectTypeSingle:
          case CBORObjectTypeDouble:
          case CBORObjectTypeExtendedDecimal:
          case CBORObjectTypeExtendedFloat:
          case CBORObjectTypeExtendedRational:
            return CBORType.Number;
          case CBORObjectTypeSimpleValue:
            return ((int)this.ThisItem == 21 || (int)this.ThisItem == 20) ?
              CBORType.Boolean : CBORType.SimpleValue;
          case CBORObjectTypeArray:
            return CBORType.Array;
          case CBORObjectTypeMap:
            return CBORType.Map;
          case CBORObjectTypeByteString:
            return CBORType.ByteString;
          case CBORObjectTypeTextString:
            return CBORType.TextString;
          default:
            throw new InvalidOperationException("Unexpected data type");
        }
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.Values"]/*'/>
    public ICollection<CBORObject> Values {
      get {
        if (this.ItemType == CBORObjectTypeMap) {
          IDictionary<CBORObject, CBORObject> dict = this.AsMap();
          return dict.Values;
        }
        if (this.ItemType == CBORObjectTypeArray) {
          IList<CBORObject> list = this.AsList();
          return new
            System.Collections.ObjectModel.ReadOnlyCollection<CBORObject>(list);
        }
        throw new InvalidOperationException("Not a map or array");
      }
    }

    internal int ItemType {
      get {
        CBORObject curobject = this;
        while (curobject.itemtypeValue == CBORObjectTypeTagged) {
          curobject = (CBORObject)curobject.itemValue;
        }
        return curobject.itemtypeValue;
      }
    }

    internal object ThisItem {
      get {
        CBORObject curobject = this;
        while (curobject.itemtypeValue == CBORObjectTypeTagged) {
          curobject = (CBORObject)curobject.itemValue;
        }
        return curobject.itemValue;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.Item(System.Int32)"]/*'/>
    public CBORObject this[int index] {
      get {
        if (this.ItemType == CBORObjectTypeArray) {
          IList<CBORObject> list = this.AsList();
          if (index < 0 || index >= list.Count) {
            throw new ArgumentOutOfRangeException(nameof(index));
          }
          return list[index];
        }
        throw new InvalidOperationException("Not an array");
      }

      set {
        if (this.ItemType == CBORObjectTypeArray) {
          if (value == null) {
            throw new ArgumentNullException(nameof(value));
          }
          IList<CBORObject> list = this.AsList();
          list[index] = value;
        } else {
          throw new InvalidOperationException("Not an array");
        }
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.Item(CBORObject)"]/*'/>
    public CBORObject this[CBORObject key] {
      get {
        if (key == null) {
          throw new ArgumentNullException(nameof(key));
        }
        if (this.ItemType == CBORObjectTypeMap) {
          IDictionary<CBORObject, CBORObject> map = this.AsMap();
          return (!map.ContainsKey(key)) ? null : map[key];
        }
        throw new InvalidOperationException("Not a map");
      }

      set {
        if (key == null) {
          throw new ArgumentNullException(nameof(value));
        }
        if (value == null) {
          throw new ArgumentNullException(nameof(value));
        }
        if (this.ItemType == CBORObjectTypeMap) {
          IDictionary<CBORObject, CBORObject> map = this.AsMap();
          map[key] = value;
        } else {
          throw new InvalidOperationException("Not a map");
        }
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.Item(System.String)"]/*'/>
    public CBORObject this[string key] {
      get {
        if (key == null) {
          throw new ArgumentNullException(nameof(key));
        }
        CBORObject objkey = CBORObject.FromObject(key);
        return this[objkey];
      }

      set {
        if (key == null) {
          throw new ArgumentNullException(nameof(value));
        }
        if (value == null) {
          throw new ArgumentNullException(nameof(value));
        }
        CBORObject objkey = CBORObject.FromObject(key);
        if (this.ItemType == CBORObjectTypeMap) {
          IDictionary<CBORObject, CBORObject> map = this.AsMap();
          map[objkey] = value;
        } else {
          throw new InvalidOperationException("Not a map");
        }
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AddConverter``1(System.Type,ICBORConverter{``0})"]/*'/>
    [Obsolete("To be replaced with the AddConverter method of CBORTypeMapper.")]
    public static void AddConverter<T>(Type type, ICBORConverter<T> converter) {
      if (type == null) {
        throw new ArgumentNullException(nameof(type));
      }
      if (converter == null) {
        throw new ArgumentNullException(nameof(converter));
      }
      ConverterInfo ci = new CBORObject.ConverterInfo();
      ci.Converter = converter;
      ci.ToObject = PropertyMap.FindOneArgumentMethod(
        converter,
        "ToCBORObject",
        type);
      if (ci.ToObject == null) {
        throw new ArgumentException(
          "Converter doesn't contain a proper ToCBORObject method");
      }
      lock (ValueConverters) {
        ValueConverters[type] = ci;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Addition(CBORObject,CBORObject)"]/*'/>
    public static CBORObject Addition(CBORObject first, CBORObject second) {
      return CBORObjectMath.Addition(first, second);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AddTagHandler(PeterO.BigInteger,ICBORTag)"]/*'/>
  [Obsolete("May be removed in the future without replacement. Not as useful as ICBORConverters and ICBORObjectConverters for FromObject and ToObject. Moreover, registering tag handlers as this method does may tie them to the lifetime of the application.")]
    public static void AddTagHandler(BigInteger bigintTag, ICBORTag handler) {
      if (bigintTag == null) {
        throw new ArgumentNullException(nameof(bigintTag));
      }
      if (handler == null) {
        throw new ArgumentNullException(nameof(handler));
      }
      AddTagHandler(PropertyMap.FromLegacy(bigintTag), handler);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AddTagHandler(PeterO.Numbers.EInteger,ICBORTag)"]/*'/>
  [Obsolete("May be removed in the future without replacement. Not as useful as ICBORConverters and ICBORObjectConverters for FromObject and ToObject. Moreover, registering tag handlers as this method does may tie them to the lifetime of the application.")]
    public static void AddTagHandler(EInteger bigintTag, ICBORTag handler) {
      if (bigintTag == null) {
        throw new ArgumentNullException(nameof(bigintTag));
      }
      if (handler == null) {
        throw new ArgumentNullException(nameof(handler));
      }
      if (bigintTag.Sign < 0) {
        throw new ArgumentException("bigintTag.Sign (" +
                    bigintTag.Sign + ") is less than 0");
      }
      if (bigintTag.GetSignedBitLength() > 64) {
        throw new ArgumentException("bigintTag.bitLength (" +
                    (long)bigintTag.GetSignedBitLength() + ") is more than " +
                    "64");
      }
      lock (ValueTagHandlers) {
        ValueTagHandlers[bigintTag] = handler;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.DecodeFromBytes(System.Byte[])"]/*'/>
    public static CBORObject DecodeFromBytes(byte[] data) {
      return DecodeFromBytes(data, new CBOREncodeOptions(true, true));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.DecodeFromBytes(System.Byte[],CBOREncodeOptions)"]/*'/>
    public static CBORObject DecodeFromBytes(
  byte[] data,
  CBOREncodeOptions options) {
      if (data == null) {
        throw new ArgumentNullException(nameof(data));
      }
      if (data.Length == 0) {
        throw new CBORException("data is empty.");
      }
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      var firstbyte = (int)(data[0] & (int)0xff);
      int expectedLength = ValueExpectedLengths[firstbyte];
      // if invalid
      if (expectedLength == -1) {
        throw new CBORException("Unexpected data encountered");
      }
      if (expectedLength != 0) {
        // if fixed length
        CheckCBORLength(expectedLength, data.Length);
      }
      if (firstbyte == 0xc0) {
        // value with tag 0
        string s = GetOptimizedStringIfShortAscii(data, 1);
        if (s != null) {
          return new CBORObject(FromObject(s), 0, 0);
        }
      }
      if (expectedLength != 0) {
        return GetFixedLengthObject(firstbyte, data);
      }
      // For objects with variable length,
      // read the object as though
      // the byte array were a stream
      using (var ms = new MemoryStream(data)) {
        CBORObject o = Read(ms, options);
        CheckCBORLength((long)data.Length, (long)ms.Position);
        return o;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Divide(CBORObject,CBORObject)"]/*'/>
    public static CBORObject Divide(CBORObject first, CBORObject second) {
      return CBORObjectMath.Divide(first, second);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromJSONString(System.String)"]/*'/>
    public static CBORObject FromJSONString(string str) {
      return FromJSONString(str, new CBOREncodeOptions(true, true));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromJSONString(System.String,CBOREncodeOptions)"]/*'/>
    public static CBORObject FromJSONString(
  string str,
  CBOREncodeOptions options) {
      if (str == null) {
        throw new ArgumentNullException(nameof(str));
      }
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      if (str.Length > 0 && str[0] == 0xfeff) {
        throw new CBORException(
          "JSON object began with a byte order mark (U+FEFF) (offset 0)");
      }
      var reader = new CharacterInputWithCount(
        new CharacterReader(str, false, true));
      var nextchar = new int[1];
      CBORObject obj = CBORJson.ParseJSONValue(
      reader,
      !options.AllowDuplicateKeys,
      false,
      nextchar);
      if (nextchar[0] != -1) {
        reader.RaiseError("End of string not reached");
      }
      return obj;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToObject(System.Type)"]/*'/>
    public object ToObject(Type t) {
      return this.ToObject(t, null, null, 0);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToObject(System.Type,CBORTypeMapper)"]/*'/>
    public object ToObject(Type t, CBORTypeMapper mapper) {
if (mapper == null) {
  throw new ArgumentNullException(nameof(mapper));
}
return this.ToObject(t, mapper, null, 0);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToObject(System.Type,PODOptions)"]/*'/>
    public object ToObject(Type t, PODOptions options) {
if (options == null) {
  throw new ArgumentNullException(nameof(options));
}
return this.ToObject(t, null, options, 0);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToObject(System.Type,CBORTypeMapper,PODOptions)"]/*'/>
    public object ToObject(Type t, CBORTypeMapper mapper, PODOptions options) {
if (mapper == null) {
  throw new ArgumentNullException(nameof(mapper));
}
if (options == null) {
  throw new ArgumentNullException(nameof(options));
}
return this.ToObject(t, mapper, options, 0);
    }

    internal object ToObject(
  Type t,
  CBORTypeMapper mapper,
  PODOptions options,
  int depth) {
depth++;
if (depth > 100) {
 throw new CBORException("Depth level too high");
}
      if (t == null) {
        throw new ArgumentNullException(nameof(t));
      }
      if (t.Equals(typeof(CBORObject))) {
        return this;
      }
      if (this.IsNull) {
        return null;
      }
      if (mapper != null) {
        object obj = mapper.ConvertBackWithConverter(this, t);
        if (obj != null) {
          return obj;
        }
      }
      if (t.Equals(typeof(object))) {
        return this;
      }
      return t.Equals(typeof(string)) ? this.AsString() :
        PropertyMap2.TypeToObject(this, t, mapper, options, depth);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Int64)"]/*'/>
    public static CBORObject FromObject(long value) {
      return (value >= 0L && value < 24L) ? valueFixedObjects[(int)value] :
        (new CBORObject(CBORObjectTypeInteger, value));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(CBORObject)"]/*'/>
    public static CBORObject FromObject(CBORObject value) {
      return value ?? CBORObject.Null;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(PeterO.BigInteger)"]/*'/>
    [Obsolete("Use the EInteger version of this method.")]
    public static CBORObject FromObject(BigInteger bigintValue) {
      return ((object)bigintValue == (object)null) ? CBORObject.Null :
        FromObject(PropertyMap.FromLegacy(bigintValue));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(PeterO.Numbers.EInteger)"]/*'/>
    public static CBORObject FromObject(EInteger bigintValue) {
      if ((object)bigintValue == (object)null) {
        return CBORObject.Null;
      }
      return (bigintValue.CompareTo(Int64MinValue) >= 0 &&
              bigintValue.CompareTo(Int64MaxValue) <= 0) ?
        new CBORObject(
          CBORObjectTypeInteger,
          (long)(EInteger)bigintValue) : (new CBORObject(
        CBORObjectTypeBigInteger,
        bigintValue));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(PeterO.ExtendedFloat)"]/*'/>
    [Obsolete("Use the EFloat version of this method instead.")]
    public static CBORObject FromObject(ExtendedFloat bigValue) {
      return ((object)bigValue == (object)null) ? CBORObject.Null :
        FromObject(PropertyMap.FromLegacy(bigValue));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(PeterO.Numbers.EFloat)"]/*'/>
    public static CBORObject FromObject(EFloat bigValue) {
      if ((object)bigValue == (object)null) {
        return CBORObject.Null;
      }
      if (bigValue.IsInfinity()) {
        return CBORObject.FromObject(bigValue.ToDouble());
      }
      if (bigValue.IsNaN()) {
        return new CBORObject(
          CBORObjectTypeExtendedFloat,
          bigValue);
      }
      EInteger bigintExponent = bigValue.Exponent;
      return (bigintExponent.IsZero && !(bigValue.IsZero &&
                    bigValue.IsNegative)) ? FromObject(bigValue.Mantissa) :
        new CBORObject(
          CBORObjectTypeExtendedFloat,
          bigValue);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(PeterO.ExtendedRational)"]/*'/>
    [Obsolete("Use the ERational version of this method instead.")]
    public static CBORObject FromObject(ExtendedRational bigValue) {
      return ((object)bigValue == (object)null) ? CBORObject.Null :
        FromObject(PropertyMap.FromLegacy(bigValue));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(PeterO.Numbers.ERational)"]/*'/>
    public static CBORObject FromObject(ERational bigValue) {
      if ((object)bigValue == (object)null) {
        return CBORObject.Null;
      }
      if (bigValue.IsInfinity()) {
        return CBORObject.FromObject(bigValue.ToDouble());
      }
      if (bigValue.IsNaN()) {
        return new CBORObject(
          CBORObjectTypeExtendedRational,
          bigValue);
      }
      return (bigValue.IsFinite && bigValue.Denominator.Equals(EInteger.One)) ?
            FromObject(bigValue.Numerator) : (new CBORObject(
              CBORObjectTypeExtendedRational,
              bigValue));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(PeterO.Numbers.EDecimal)"]/*'/>
    public static CBORObject FromObject(EDecimal otherValue) {
      if ((object)otherValue == (object)null) {
        return CBORObject.Null;
      }
      if (otherValue.IsInfinity()) {
        return CBORObject.FromObject(otherValue.ToDouble());
      }
      if (otherValue.IsNaN()) {
        return new CBORObject(
          CBORObjectTypeExtendedDecimal,
          otherValue);
      }
      EInteger bigintExponent = otherValue.Exponent;
      return (bigintExponent.IsZero && !(otherValue.IsZero &&
                    otherValue.IsNegative)) ? FromObject(otherValue.Mantissa) :
        new CBORObject(
          CBORObjectTypeExtendedDecimal,
          otherValue);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(PeterO.ExtendedDecimal)"]/*'/>
    [Obsolete("Use the EDecimal version of this method instead.")]
    public static CBORObject FromObject(ExtendedDecimal otherValue) {
      return ((object)otherValue == (object)null) ? CBORObject.Null :
        FromObject(PropertyMap.FromLegacy(otherValue));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.String)"]/*'/>
    public static CBORObject FromObject(string strValue) {
      if (strValue == null) {
        return CBORObject.Null;
      }
      if (DataUtilities.GetUtf8Length(strValue, false) < 0) {
        throw new
        ArgumentException("String contains an unpaired surrogate code point.");
      }
      return new CBORObject(CBORObjectTypeTextString, strValue);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Int32)"]/*'/>
    public static CBORObject FromObject(int value) {
      return (value >= 0 && value < 24) ? valueFixedObjects[value] :
        FromObject((long)value);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Int16)"]/*'/>
    public static CBORObject FromObject(short value) {
      return (value >= 0 && value < 24) ? valueFixedObjects[value] :
        FromObject((long)value);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Char)"]/*'/>
    public static CBORObject FromObject(char value) {
      char[] valueChar = { value };
      return FromObject(new String(valueChar));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Boolean)"]/*'/>
    public static CBORObject FromObject(bool value) {
      return value ? CBORObject.True : CBORObject.False;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Byte)"]/*'/>
    public static CBORObject FromObject(byte value) {
      return FromObject(((int)value) & 0xff);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Single)"]/*'/>
    public static CBORObject FromObject(float value) {
      return new CBORObject(CBORObjectTypeSingle, value);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Double)"]/*'/>
    public static CBORObject FromObject(double value) {
      return new CBORObject(CBORObjectTypeDouble, value);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Byte[])"]/*'/>
    public static CBORObject FromObject(byte[] bytes) {
      if (bytes == null) {
        return CBORObject.Null;
      }
      var newvalue = new byte[bytes.Length];
      Array.Copy(bytes, 0, newvalue, 0, bytes.Length);
      return new CBORObject(CBORObjectTypeByteString, bytes);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(CBORObject[])"]/*'/>
    public static CBORObject FromObject(CBORObject[] array) {
      if (array == null) {
        return CBORObject.Null;
      }
      IList<CBORObject> list = new List<CBORObject>();
      foreach (CBORObject i in array) {
        list.Add(FromObject(i));
      }
      return new CBORObject(CBORObjectTypeArray, list);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Int32[])"]/*'/>
    public static CBORObject FromObject(int[] array) {
      if (array == null) {
        return CBORObject.Null;
      }
      IList<CBORObject> list = new List<CBORObject>();
      foreach (int i in array) {
        list.Add(FromObject(i));
      }
      return new CBORObject(CBORObjectTypeArray, list);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Int64[])"]/*'/>
    public static CBORObject FromObject(long[] array) {
      if (array == null) {
        return CBORObject.Null;
      }
      IList<CBORObject> list = new List<CBORObject>();
      foreach (long i in array) {
        // Console.WriteLine(i);
        list.Add(FromObject(i));
      }
      return new CBORObject(CBORObjectTypeArray, list);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject``1(System.Collections.Generic.IList{``0})"]/*'/>
    public static CBORObject FromObject<T>(IList<T> value) {
      if (value == null) {
        return CBORObject.Null;
      }
      CBORObject retCbor = CBORObject.NewArray();
      foreach (T i in (IList<T>)value) {
        retCbor.Add(CBORObject.FromObject(i));
      }
      return retCbor;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject``1(System.Collections.Generic.IEnumerable{``0})"]/*'/>
    public static CBORObject FromObject<T>(IEnumerable<T> value) {
      if (value == null) {
        return CBORObject.Null;
      }
      CBORObject retCbor = CBORObject.NewArray();
      foreach (T i in (IEnumerable<T>)value) {
        retCbor.Add(CBORObject.FromObject(i));
      }
      return retCbor;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject``2(System.Collections.Generic.IDictionary{``0,``1})"]/*'/>
    public static CBORObject FromObject<TKey, TValue>(IDictionary<TKey,
                    TValue> dic) {
      if (dic == null) {
        return CBORObject.Null;
      }
      var map = new Dictionary<CBORObject, CBORObject>();
      foreach (KeyValuePair<TKey, TValue> entry in dic) {
        CBORObject key = FromObject(entry.Key);
        CBORObject value = FromObject(entry.Value);
        map[key] = value;
      }
      return new CBORObject(CBORObjectTypeMap, map);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Object)"]/*'/>
    public static CBORObject FromObject(object obj) {
      return FromObject(obj, PODOptions.Default);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObject(System.Object,PODOptions)"]/*'/>
    public static CBORObject FromObject(
  object obj,
  PODOptions options) {
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      if (obj == null) {
        return CBORObject.Null;
      }
      if (obj is string) {
        return FromObject((string)obj);
      }
      if (obj is int) {
        return FromObject((int)obj);
      }
      if (obj is long) {
        return FromObject((long)obj);
      }
      if (obj is CBORObject) {
        return FromObject((CBORObject)obj);
      }
      var eif = obj as EInteger;
      if (eif != null) {
        return FromObject(eif);
      }
      var edf = obj as EDecimal;
      if (edf != null) {
        return FromObject(edf);
      }
      var eff = obj as EFloat;
      if (eff != null) {
        return FromObject(eff);
      }
      var erf = obj as ERational;
      if (erf != null) {
        return FromObject(erf);
      }
#pragma warning disable 618
      var bi = obj as BigInteger;
      if (bi != null) {
        return FromObject(bi);
      }
      var df = obj as ExtendedDecimal;
      if (df != null) {
        return FromObject(df);
      }
      var bf = obj as ExtendedFloat;
      if (bf != null) {
        return FromObject(bf);
      }
      var rf = obj as ExtendedRational;
      if (rf != null) {
        return FromObject(rf);
      }
#pragma warning restore 618
      if (obj is short) {
        return FromObject((short)obj);
      }
      if (obj is char) {
        return FromObject((char)obj);
      }
      if (obj is bool) {
        return FromObject((bool)obj);
      }
      if (obj is byte) {
        return FromObject((byte)obj);
      }
      if (obj is float) {
        return FromObject((float)obj);
      }
      if (obj is sbyte) {
        return FromObject((sbyte)obj);
      }
      if (obj is ulong) {
        return FromObject((ulong)obj);
      }
      if (obj is uint) {
        return FromObject((uint)obj);
      }
      if (obj is ushort) {
        return FromObject((ushort)obj);
      }
      if (obj is decimal) {
        return FromObject((decimal)obj);
      }
      if (obj is Enum) {
        return FromObject(PropertyMap.EnumToObject((Enum)obj));
      }
      if (obj is double) {
        return FromObject((double)obj);
      }
      byte[] bytearr = obj as byte[];
      if (bytearr != null) {
        return FromObject(bytearr);
      }
      CBORObject objret;
      if (obj is System.Collections.IDictionary) {
        // IDictionary appears first because IDictionary includes IEnumerable
        objret = CBORObject.NewMap();
        System.Collections.IDictionary objdic =
          (System.Collections.IDictionary)obj;
        foreach (object keyPair in (System.Collections.IDictionary)objdic) {
          System.Collections.DictionaryEntry
            kvp = (System.Collections.DictionaryEntry)keyPair;
          CBORObject objKey = CBORObject.FromObject(kvp.Key, options);
          objret[objKey] = CBORObject.FromObject(kvp.Value, options);
        }
        return objret;
      }
      if (obj is Array) {
        return PropertyMap.FromArray(obj, options);
      }
      if (obj is System.Collections.IEnumerable) {
        objret = CBORObject.NewArray();
        foreach (object element in (System.Collections.IEnumerable)obj) {
          objret.Add(CBORObject.FromObject(element, options));
        }
        return objret;
      }
      objret = ConvertWithConverter(obj);
      if (objret != null) {
        return objret;
      }
      objret = CBORObject.NewMap();
        #pragma warning disable 618
      foreach (KeyValuePair<string, object> key in
               PropertyMap.GetProperties(
                 obj,
                 options.RemoveIsPrefix,
                 options.UseCamelCase)) {
        objret[key.Key] = CBORObject.FromObject(key.Value, options);
      }
        #pragma warning restore 618
      return objret;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObjectAndTag(System.Object,PeterO.BigInteger)"]/*'/>
    [Obsolete("Use the EInteger version instead.")]
    public static CBORObject FromObjectAndTag(
      object valueOb,
      BigInteger bigintTag) {
      if (bigintTag == null) {
        throw new ArgumentNullException(nameof(bigintTag));
      }
      return FromObjectAndTag(valueOb, PropertyMap.FromLegacy(bigintTag));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObjectAndTag(System.Object,PeterO.Numbers.EInteger)"]/*'/>
    public static CBORObject FromObjectAndTag(
      object valueOb,
      EInteger bigintTag) {
      if (bigintTag == null) {
        throw new ArgumentNullException(nameof(bigintTag));
      }
      if (bigintTag.Sign < 0) {
        throw new ArgumentException("tagEInt's sign (" + bigintTag.Sign +
                    ") is less than 0");
      }
      if (bigintTag.CompareTo(UInt64MaxValue) > 0) {
        throw new ArgumentException(
          "tag more than 18446744073709551615 (" + bigintTag + ")");
      }
      CBORObject c = FromObject(valueOb);
      if (bigintTag.GetSignedBitLength() <= 16) {
        // Low-numbered, commonly used tags
        return FromObjectAndTag(c, bigintTag.ToInt32Checked());
      } else {
        var tagLow = 0;
        var tagHigh = 0;
        byte[] bytes = bigintTag.ToBytes(true);
        for (var i = 0; i < Math.Min(4, bytes.Length); ++i) {
          int b = ((int)bytes[i]) & 0xff;
          tagLow = unchecked(tagLow | (((int)b) << (i * 8)));
        }
        for (int i = 4; i < Math.Min(8, bytes.Length); ++i) {
          int b = ((int)bytes[i]) & 0xff;
          tagHigh = unchecked(tagHigh | (((int)b) << (i * 8)));
        }
        var c2 = new CBORObject(c, tagLow, tagHigh);
        #pragma warning disable 618
        ICBORTag tagconv = FindTagConverter(bigintTag);
        #pragma warning restore 618
        if (tagconv != null) {
          c2 = tagconv.ValidateObject(c2);
        }
        return c2;
      }
    }

      #pragma warning disable 612
      #pragma warning disable 618
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromObjectAndTag(System.Object,System.Int32)"]/*'/>
    public static CBORObject FromObjectAndTag(
      object valueObValue,
      int smallTag) {
      if (smallTag < 0) {
        throw new ArgumentException("smallTag (" + smallTag +
                    ") is less than 0");
      }
      ICBORTag tagconv = FindTagConverter(smallTag);
      CBORObject c = FromObject(valueObValue);
      c = new CBORObject(c, smallTag, 0);
      return (tagconv != null) ? tagconv.ValidateObject(c) : c;
    }
      #pragma warning restore 618
      #pragma warning restore 612

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.FromSimpleValue(System.Int32)"]/*'/>
    public static CBORObject FromSimpleValue(int simpleValue) {
      if (simpleValue < 0) {
        throw new ArgumentException("simpleValue (" + simpleValue +
                    ") is less than 0");
      }
      if (simpleValue > 255) {
        throw new ArgumentException("simpleValue (" + simpleValue +
                    ") is more than " + "255");
      }
      if (simpleValue >= 24 && simpleValue < 32) {
        throw new ArgumentException("Simple value is from 24 to 31: " +
                    simpleValue);
      }
      if (simpleValue < 32) {
        return valueFixedObjects[0xe0 + simpleValue];
      }
      return new CBORObject(
        CBORObjectTypeSimpleValue,
        simpleValue);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Multiply(CBORObject,CBORObject)"]/*'/>
    public static CBORObject Multiply(CBORObject first, CBORObject second) {
      return CBORObjectMath.Multiply(first, second);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.NewArray"]/*'/>
    public static CBORObject NewArray() {
      return new CBORObject(CBORObjectTypeArray, new List<CBORObject>());
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.NewMap"]/*'/>
    public static CBORObject NewMap() {
      return FromObject(new Dictionary<CBORObject, CBORObject>());
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Read(System.IO.Stream)"]/*'/>
    public static CBORObject Read(Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      try {
        var reader = new CBORReader(stream);
        return reader.ResolveSharedRefsIfNeeded(reader.Read(null));
      } catch (IOException ex) {
        throw new CBORException("I/O error occurred.", ex);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Read(System.IO.Stream,CBOREncodeOptions)"]/*'/>
    public static CBORObject Read(Stream stream, CBOREncodeOptions options) {
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      try {
        var reader = new CBORReader(stream);
        if (!options.AllowDuplicateKeys) {
          reader.DuplicatePolicy = CBORReader.CBORDuplicatePolicy.Disallow;
        }
        return reader.ResolveSharedRefsIfNeeded(reader.Read(null));
      } catch (IOException ex) {
        throw new CBORException("I/O error occurred.", ex);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ReadJSON(System.IO.Stream)"]/*'/>
    public static CBORObject ReadJSON(Stream stream) {
      return ReadJSON(stream, new CBOREncodeOptions(true, true));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ReadJSON(System.IO.Stream,CBOREncodeOptions)"]/*'/>
    public static CBORObject ReadJSON(
  Stream stream,
  CBOREncodeOptions options) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      var reader = new CharacterInputWithCount(
        new CharacterReader(stream, 2, true));
      try {
        var nextchar = new int[1];
        CBORObject obj = CBORJson.ParseJSONValue(
     reader,
     !options.AllowDuplicateKeys,
     false,
     nextchar);
        if (nextchar[0] != -1) {
          reader.RaiseError("End of data stream not reached");
        }
        return obj;
      } catch (CBORException ex) {
        var ioex = ex.InnerException as IOException;
        if (ioex != null) {
          throw ioex;
        }
        throw;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Remainder(CBORObject,CBORObject)"]/*'/>
    public static CBORObject Remainder(CBORObject first, CBORObject second) {
      return CBORObjectMath.Remainder(first, second);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Subtract(CBORObject,CBORObject)"]/*'/>
    public static CBORObject Subtract(CBORObject first, CBORObject second) {
      return CBORObjectMath.Subtract(first, second);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.String,System.IO.Stream)"]/*'/>
    public static void Write(string str, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      // TODO: Use CBOREncodeOptions.Default in future versions
      Write(str, stream, new CBOREncodeOptions(true, true));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.String,System.IO.Stream,CBOREncodeOptions)"]/*'/>
    public static void Write(
      string str,
      Stream stream,
      CBOREncodeOptions options) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      if (str == null) {
        stream.WriteByte(0xf6);  // Write null instead of string
      } else {
        if (!options.UseIndefLengthStrings || options.Ctap2Canonical) {
          // NOTE: Length of a String object won't be higher than the maximum
          // allowed for definite-length strings
          long codePointLength = DataUtilities.GetUtf8Length(str, true);
          WritePositiveInt64(3, codePointLength, stream);
          DataUtilities.WriteUtf8(str, stream, true);
        } else {
          WriteStreamedString(str, stream);
        }
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(PeterO.ExtendedFloat,System.IO.Stream)"]/*'/>
    [Obsolete("Pass an EFloat to the Write method instead.")]
    public static void Write(ExtendedFloat bignum, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (bignum == null) {
        stream.WriteByte(0xf6);
        return;
      }
      Write(PropertyMap.FromLegacy(bignum), stream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(PeterO.Numbers.EFloat,System.IO.Stream)"]/*'/>
    public static void Write(EFloat bignum, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (bignum == null) {
        stream.WriteByte(0xf6);
        return;
      }
      if ((bignum.IsZero && bignum.IsNegative) || bignum.IsInfinity() ||
          bignum.IsNaN()) {
        Write(bignum.ToDouble(), stream);
        return;
      }
      EInteger exponent = bignum.Exponent;
      if (exponent.IsZero) {
        Write(bignum.Mantissa, stream);
      } else {
        if (!BigIntFits(exponent)) {
          stream.WriteByte(0xd9);  // tag 265
          stream.WriteByte(0x01);
          stream.WriteByte(0x09);
          stream.WriteByte(0x82);  // array, length 2
        } else {
          stream.WriteByte(0xc5);  // tag 5
          stream.WriteByte(0x82);  // array, length 2
        }
        Write(bignum.Exponent, stream);
        Write(bignum.Mantissa, stream);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(PeterO.ExtendedRational,System.IO.Stream)"]/*'/>
    [Obsolete("Pass an ERational to the Write method instead.")]
    public static void Write(ExtendedRational rational, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (rational == null) {
        stream.WriteByte(0xf6);
        return;
      }
      Write(PropertyMap.FromLegacy(rational), stream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(PeterO.Numbers.ERational,System.IO.Stream)"]/*'/>
    public static void Write(ERational rational, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (rational == null) {
        stream.WriteByte(0xf6);
        return;
      }
      if (!rational.IsFinite || (rational.IsNegative && rational.IsZero)) {
        Write(rational.ToDouble(), stream);
        return;
      }
      if (rational.Denominator.Equals(EInteger.One)) {
        Write(rational.Numerator, stream);
        return;
      }
      stream.WriteByte(0xd8);  // tag 30
      stream.WriteByte(0x1e);
      stream.WriteByte(0x82);  // array, length 2
      Write(rational.Numerator, stream);
      Write(rational.Denominator, stream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(PeterO.ExtendedDecimal,System.IO.Stream)"]/*'/>
    [Obsolete("Pass an EDecimal to the Write method instead.")]
    public static void Write(ExtendedDecimal bignum, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (bignum == null) {
        stream.WriteByte(0xf6);
        return;
      }
      Write(PropertyMap.FromLegacy(bignum), stream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(PeterO.Numbers.EDecimal,System.IO.Stream)"]/*'/>
    public static void Write(EDecimal bignum, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (bignum == null) {
        stream.WriteByte(0xf6);
        return;
      }
      if ((bignum.IsZero && bignum.IsNegative) || bignum.IsInfinity() ||
          bignum.IsNaN()) {
        Write(bignum.ToDouble(), stream);
        return;
      }
      EInteger exponent = bignum.Exponent;
      if (exponent.IsZero) {
        Write(bignum.Mantissa, stream);
      } else {
        if (!BigIntFits(exponent)) {
          stream.WriteByte(0xd9);  // tag 264
          stream.WriteByte(0x01);
          stream.WriteByte(0x08);
          stream.WriteByte(0x82);  // array, length 2
        } else {
          stream.WriteByte(0xc4);  // tag 4
          stream.WriteByte(0x82);  // array, length 2
        }
        Write(bignum.Exponent, stream);
        Write(bignum.Mantissa, stream);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(PeterO.BigInteger,System.IO.Stream)"]/*'/>
    [Obsolete("Pass an EInteger to the Write method instead.")]
    public static void Write(BigInteger bigint, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if ((object)bigint == (object)null) {
        stream.WriteByte(0xf6);
        return;
      }
      Write(PropertyMap.FromLegacy(bigint), stream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(PeterO.Numbers.EInteger,System.IO.Stream)"]/*'/>
    public static void Write(EInteger bigint, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if ((object)bigint == (object)null) {
        stream.WriteByte(0xf6);
        return;
      }
      var datatype = 0;
      if (bigint.Sign < 0) {
        datatype = 1;
        bigint = bigint.Add(EInteger.One);
        bigint = -(EInteger)bigint;
      }
      if (bigint.CompareTo(Int64MaxValue) <= 0) {
        // If the big integer is representable as a long and in
        // major type 0 or 1, write that major type
        // instead of as a bignum
        var ui = (long)(EInteger)bigint;
        WritePositiveInt64(datatype, ui, stream);
      } else {
        // Get a byte array of the big integer's value,
        // since shifting and doing AND operations is
        // slow with large BigIntegers
        byte[] bytes = bigint.ToBytes(true);
        int byteCount = bytes.Length;
        while (byteCount > 0 && bytes[byteCount - 1] == 0) {
          // Ignore trailing zero bytes
          --byteCount;
        }
        if (byteCount != 0) {
          int half = byteCount >> 1;
          int right = byteCount - 1;
          for (var i = 0; i < half; ++i, --right) {
            byte value = bytes[i];
            bytes[i] = bytes[right];
            bytes[right] = value;
          }
        }
        switch (byteCount) {
          case 0:
            stream.WriteByte((byte)(datatype << 5));
            return;
          case 1:
            WritePositiveInt(datatype, ((int)bytes[0]) & 0xff, stream);
            break;
          case 2:
            stream.WriteByte((byte)((datatype << 5) | 25));
            stream.Write(bytes, 0, byteCount);
            break;
          case 3:
            stream.WriteByte((byte)((datatype << 5) | 26));
            stream.WriteByte((byte)0);
            stream.Write(bytes, 0, byteCount);
            break;
          case 4:
            stream.WriteByte((byte)((datatype << 5) | 26));
            stream.Write(bytes, 0, byteCount);
            break;
          case 5:
            stream.WriteByte((byte)((datatype << 5) | 27));
            stream.WriteByte((byte)0);
            stream.WriteByte((byte)0);
            stream.WriteByte((byte)0);
            stream.Write(bytes, 0, byteCount);
            break;
          case 6:
            stream.WriteByte((byte)((datatype << 5) | 27));
            stream.WriteByte((byte)0);
            stream.WriteByte((byte)0);
            stream.Write(bytes, 0, byteCount);
            break;
          case 7:
            stream.WriteByte((byte)((datatype << 5) | 27));
            stream.WriteByte((byte)0);
            stream.Write(bytes, 0, byteCount);
            break;
          case 8:
            stream.WriteByte((byte)((datatype << 5) | 27));
            stream.Write(bytes, 0, byteCount);
            break;
          default: stream.WriteByte((datatype == 0) ?
(byte)0xc2 : (byte)0xc3);
            WritePositiveInt(2, byteCount, stream);
            stream.Write(bytes, 0, byteCount);
            break;
        }
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.Int64,System.IO.Stream)"]/*'/>
    public static void Write(long value, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (value >= 0) {
        WritePositiveInt64(0, value, stream);
      } else {
        ++value;
        value = -value;  // Will never overflow
        WritePositiveInt64(1, value, stream);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.Int32,System.IO.Stream)"]/*'/>
    public static void Write(int value, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      var type = 0;
      if (value < 0) {
        ++value;
        value = -value;
        type = 0x20;
      }
      if (value < 24) {
        stream.WriteByte((byte)(value | type));
      } else if (value <= 0xff) {
        byte[] bytes = { (byte)(24 | type), (byte)(value & 0xff) };
        stream.Write(bytes, 0, 2);
      } else if (value <= 0xffff) {
        byte[] bytes = { (byte)(25 | type), (byte)((value >> 8) & 0xff),
          (byte)(value & 0xff) };
        stream.Write(bytes, 0, 3);
      } else {
        byte[] bytes = { (byte)(26 | type), (byte)((value >> 24) & 0xff),
          (byte)((value >> 16) & 0xff), (byte)((value >> 8) & 0xff),
          (byte)(value & 0xff) };
        stream.Write(bytes, 0, 5);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.Int16,System.IO.Stream)"]/*'/>
    public static void Write(short value, Stream stream) {
      Write((long)value, stream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.Char,System.IO.Stream)"]/*'/>
    public static void Write(char value, Stream stream) {
      if (value >= 0xd800 && value < 0xe000) {
        throw new ArgumentException("Value is a surrogate code point.");
      }
      char[] valueChar = { value };
      Write(new String(valueChar), stream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.Boolean,System.IO.Stream)"]/*'/>
    public static void Write(bool value, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      stream.WriteByte(value ? (byte)0xf5 : (byte)0xf4);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.Byte,System.IO.Stream)"]/*'/>
    public static void Write(byte value, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if ((((int)value) & 0xff) < 24) {
        stream.WriteByte(value);
      } else {
        stream.WriteByte((byte)24);
        stream.WriteByte(value);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.Single,System.IO.Stream)"]/*'/>
    public static void Write(float value, Stream s) {
      if (s == null) {
        throw new ArgumentNullException(nameof(s));
      }
      int bits = BitConverter.ToInt32(BitConverter.GetBytes((float)value), 0);
      byte[] data = { (byte)0xfa, (byte)((bits >> 24) & 0xff),
        (byte)((bits >> 16) & 0xff), (byte)((bits >> 8) & 0xff),
        (byte)(bits & 0xff) };
      s.Write(data, 0, 5);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.Double,System.IO.Stream)"]/*'/>
    public static void Write(double value, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      long bits =
        BitConverter.ToInt64(
          BitConverter.GetBytes((double)value),
          0);
      byte[] data = { (byte)0xfb,
        (byte)((bits >> 56) & 0xff), (byte)((bits >> 48) & 0xff),
        (byte)((bits >> 40) & 0xff), (byte)((bits >> 32) & 0xff),
        (byte)((bits >> 24) & 0xff), (byte)((bits >> 16) & 0xff),
        (byte)((bits >> 8) & 0xff), (byte)(bits & 0xff) };
      stream.Write(data, 0, 9);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(CBORObject,System.IO.Stream)"]/*'/>
    public static void Write(CBORObject value, Stream stream) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (value == null) {
        stream.WriteByte(0xf6);
      } else {
        value.WriteTo(stream);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.Object,System.IO.Stream)"]/*'/>
    public static void Write(object objValue, Stream stream) {
      // TODO: Use CBOREncodeOptions.Default in future versions
      Write(objValue, stream, new CBOREncodeOptions(true, true));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Write(System.Object,System.IO.Stream,CBOREncodeOptions)"]/*'/>
    public static void Write(
      object objValue,
      Stream output,
      CBOREncodeOptions options) {
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      if (output == null) {
        throw new ArgumentNullException(nameof(output));
      }
      if (objValue == null) {
        output.WriteByte(0xf6);
        return;
      }
      if (options.Ctap2Canonical) {
        FromObject(objValue).WriteTo(output, options);
        return;
      }
      byte[] data = objValue as byte[];
      if (data != null) {
        WritePositiveInt(3, data.Length, output);
        output.Write(data, 0, data.Length);
        return;
      }
      if (objValue is IList<CBORObject>) {
        WriteObjectArray(
          (IList<CBORObject>)objValue,
          output,
          options);
        return;
      }
      if (objValue is IDictionary<CBORObject, CBORObject>) {
        WriteObjectMap(
          (IDictionary<CBORObject, CBORObject>)objValue,
          output,
          options);
        return;
      }
      FromObject(objValue).WriteTo(output, options);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.WriteJSON(System.Object,System.IO.Stream)"]/*'/>
    public static void WriteJSON(object obj, Stream outputStream) {
      if (obj == null) {
        outputStream.Write(ValueNullBytes, 0, ValueNullBytes.Length);
        return;
      }
      if (obj is bool) {
        if ((bool)obj) {
          outputStream.Write(ValueTrueBytes, 0, ValueTrueBytes.Length);
          return;
        }
        outputStream.Write(ValueFalseBytes, 0, ValueFalseBytes.Length);
        return;
      }
      CBORObject.FromObject(obj).WriteJSONTo(outputStream);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Abs"]/*'/>
    public CBORObject Abs() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("This object is not a number.");
      }
      object oldItem = this.ThisItem;
      object newItem = cn.Abs(oldItem);
      if (oldItem == newItem) {
        return this;
      }
      if (newItem is EDecimal) {
        return CBORObject.FromObject((EDecimal)newItem);
      }
      if (newItem is EInteger) {
        return CBORObject.FromObject((EInteger)newItem);
      }
      if (newItem is EFloat) {
        return CBORObject.FromObject((EFloat)newItem);
      }
      var rat = newItem as ERational;
      return (rat != null) ? CBORObject.FromObject(rat) : ((oldItem ==
          newItem) ? this : CBORObject.FromObject(newItem));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Add(System.Object,System.Object)"]/*'/>
    public CBORObject Add(object key, object valueOb) {
      if (this.ItemType == CBORObjectTypeMap) {
        CBORObject mapKey;
        CBORObject mapValue;
        if (key == null) {
          mapKey = CBORObject.Null;
        } else {
          mapKey = key as CBORObject;
          mapKey = mapKey ?? CBORObject.FromObject(key);
        }
        if (valueOb == null) {
          mapValue = CBORObject.Null;
        } else {
          mapValue = valueOb as CBORObject;
          mapValue = mapValue ?? CBORObject.FromObject(valueOb);
        }
        IDictionary<CBORObject, CBORObject> map = this.AsMap();
        if (map.ContainsKey(mapKey)) {
          throw new ArgumentException("Key already exists");
        }
        map.Add(mapKey, mapValue);
      } else {
        throw new InvalidOperationException("Not a map");
      }
      return this;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Add(CBORObject)"]/*'/>
    public CBORObject Add(CBORObject obj) {
      if (this.ItemType == CBORObjectTypeArray) {
        IList<CBORObject> list = this.AsList();
        list.Add(obj);
        return this;
      }
      throw new InvalidOperationException("Not an array");
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Add(System.Object)"]/*'/>
    public CBORObject Add(object obj) {
      if (this.ItemType == CBORObjectTypeArray) {
        IList<CBORObject> list = this.AsList();
        list.Add(CBORObject.FromObject(obj));
        return this;
      }
      throw new InvalidOperationException("Not an array");
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsBigInteger"]/*'/>
    [Obsolete("Use the AsEInteger method instead.")]
    public BigInteger AsBigInteger() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("Not a number type");
      }
      return BigInteger.fromBytes(
        cn.AsEInteger(this.ThisItem).ToBytes(true),
        true);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsEInteger"]/*'/>
    public EInteger AsEInteger() {
      // TODO: Consider returning null if this object is null
      // in next major version
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("Not a number type");
      }
      return cn.AsEInteger(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsBoolean"]/*'/>
    public bool AsBoolean() {
      return !this.IsFalse && !this.IsNull && !this.IsUndefined;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsByte"]/*'/>
    public byte AsByte() {
      return (byte)this.AsInt32(0, 255);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsDouble"]/*'/>
    public double AsDouble() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("Not a number type");
      }
      return cn.AsDouble(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsExtendedDecimal"]/*'/>
    [Obsolete("Use AsEDecimal instead.")]
    public ExtendedDecimal AsExtendedDecimal() {
      return ExtendedDecimal.FromString(this.AsEDecimal().ToString());
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsEDecimal"]/*'/>
    public EDecimal AsEDecimal() {
      // TODO: Consider returning null if this object is null
      // in next major version
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("Not a number type");
      }
      return cn.AsExtendedDecimal(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsExtendedFloat"]/*'/>
    [Obsolete("Use AsEFloat instead.")]
    public ExtendedFloat AsExtendedFloat() {
      return ExtendedFloat.FromString(this.AsEFloat().ToString());
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsEFloat"]/*'/>
    public EFloat AsEFloat() {
      // TODO: Consider returning null if this object is null
      // in next major version
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("Not a number type");
      }
      return cn.AsExtendedFloat(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsExtendedRational"]/*'/>
    [Obsolete("Use AsERational instead.")]
    public ExtendedRational AsExtendedRational() {
      return PropertyMap.ToLegacy(this.AsERational());
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsERational"]/*'/>
    // TODO: Consider returning null if this object is null
    // in next major version
    public ERational AsERational() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("Not a number type");
      }
      return cn.AsExtendedRational(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsInt16"]/*'/>
    public short AsInt16() {
      return (short)this.AsInt32(Int16.MinValue, Int16.MaxValue);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsInt32"]/*'/>
    public int AsInt32() {
      return this.AsInt32(Int32.MinValue, Int32.MaxValue);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsInt64"]/*'/>
    public long AsInt64() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("Not a number type");
      }
      return cn.AsInt64(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsSingle"]/*'/>
    public float AsSingle() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("Not a number type");
      }
      return cn.AsSingle(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.AsString"]/*'/>
    public string AsString() {
      // TODO: Consider returning null if this object is null
      // in next major version
      int type = this.ItemType;
      switch (type) {
        case CBORObjectTypeTextString: {
            return (string)this.ThisItem;
          }
        default: throw new InvalidOperationException("Not a string type");
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.CanFitInDouble"]/*'/>
    public bool CanFitInDouble() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      return (cn != null) && cn.CanFitInDouble(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.CanFitInInt32"]/*'/>
    public bool CanFitInInt32() {
      if (!this.CanFitInInt64()) {
        return false;
      }
      long v = this.AsInt64();
      return v >= Int32.MinValue && v <= Int32.MaxValue;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.CanFitInInt64"]/*'/>
    public bool CanFitInInt64() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      return (cn != null) && cn.CanFitInInt64(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.CanFitInSingle"]/*'/>
    public bool CanFitInSingle() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      return (cn != null) && cn.CanFitInSingle(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.CanTruncatedIntFitInInt32"]/*'/>
    public bool CanTruncatedIntFitInInt32() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      return (cn != null) && cn.CanTruncatedIntFitInInt32(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.CanTruncatedIntFitInInt64"]/*'/>
    public bool CanTruncatedIntFitInInt64() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      return cn != null && cn.CanTruncatedIntFitInInt64(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.CompareTo(CBORObject)"]/*'/>
    public int CompareTo(CBORObject other) {
      if (other == null) {
        return 1;
      }
      if (this == other) {
        return 0;
      }
      int typeA = this.ItemType;
      int typeB = other.ItemType;
      object objA = this.ThisItem;
      object objB = other.ThisItem;
      var simpleValueA = -1;
      var simpleValueB = -1;
      if (typeA == CBORObjectTypeSimpleValue) {
        if ((int)objA == 20) {  // false
          simpleValueA = 2;
        } else if ((int)objA == 21) {  // true
          simpleValueA = 3;
        } else if ((int)objA == 22) {  // null
          simpleValueA = 1;
        } else if ((int)objA == 23) {  // undefined
          simpleValueA = 0;
        }
      }
      if (typeB == CBORObjectTypeSimpleValue) {
        if ((int)objB == 20) {  // false
          simpleValueB = 2;
        } else if ((int)objB == 21) {  // true
          simpleValueB = 3;
        } else if ((int)objB == 22) {  // null
          simpleValueB = 1;
        } else if ((int)objB == 23) {  // undefined
          simpleValueB = 0;
        }
      }
      var cmp = 0;
      if (simpleValueA >= 0 || simpleValueB >= 0) {
        if (simpleValueB < 0) {
          return -1;  // B is not true, false, null, or undefined, so A is less
        }
        if (simpleValueA < 0) {
          return 1;
        }
        cmp = (simpleValueA == simpleValueB) ? 0 : ((simpleValueA <
                    simpleValueB) ? -1 : 1);
      } else if (typeA == typeB) {
        switch (typeA) {
          case CBORObjectTypeInteger: {
              var a = (long)objA;
              var b = (long)objB;
              cmp = (a == b) ? 0 : ((a < b) ? -1 : 1);
              break;
            }
          case CBORObjectTypeSingle: {
              var a = (float)objA;
              var b = (float)objB;
              // Treat NaN as greater than all other numbers
              cmp = Single.IsNaN(a) ? (Single.IsNaN(b) ? 0 : 1) :
                (Single.IsNaN(b) ? (-1) : ((a == b) ? 0 : ((a < b) ? -1 :
                    1)));
              break;
            }
          case CBORObjectTypeBigInteger: {
              var bigintA = (EInteger)objA;
              var bigintB = (EInteger)objB;
              cmp = bigintA.CompareTo(bigintB);
              break;
            }
          case CBORObjectTypeDouble: {
              var a = (double)objA;
              var b = (double)objB;
              // Treat NaN as greater than all other numbers
              cmp = Double.IsNaN(a) ? (Double.IsNaN(b) ? 0 : 1) :
                (Double.IsNaN(b) ? (-1) : ((a == b) ? 0 : ((a < b) ? -1 :
                    1)));
              break;
            }
          case CBORObjectTypeExtendedDecimal: {
              cmp = ((EDecimal)objA).CompareTo((EDecimal)objB);
              break;
            }
          case CBORObjectTypeExtendedFloat: {
              cmp = ((EFloat)objA).CompareTo(
                (EFloat)objB);
              break;
            }
          case CBORObjectTypeExtendedRational: {
              cmp = ((ERational)objA).CompareTo(
                (ERational)objB);
              break;
            }
          case CBORObjectTypeByteString: {
              cmp = CBORUtilities.ByteArrayCompare((byte[])objA, (byte[])objB);
              break;
            }
          case CBORObjectTypeTextString: {
              cmp = DataUtilities.CodePointCompare(
                (string)objA,
                (string)objB);
              break;
            }
          case CBORObjectTypeArray: {
              cmp = ListCompare(
                (List<CBORObject>)objA,
                (List<CBORObject>)objB);
              break;
            }
          case CBORObjectTypeMap: {
              cmp = MapCompare(
                (IDictionary<CBORObject, CBORObject>)objA,
                (IDictionary<CBORObject, CBORObject>)objB);
              break;
            }
          case CBORObjectTypeSimpleValue: {
              var valueA = (int)objA;
              var valueB = (int)objB;
              cmp = (valueA == valueB) ? 0 : ((valueA < valueB) ? -1 : 1);
              break;
            }
          default: throw new ArgumentException("Unexpected data type");
        }
      } else {
        int typeOrderA = ValueNumberTypeOrder[typeA];
        int typeOrderB = ValueNumberTypeOrder[typeB];
        // Check whether general types are different
        // (treating number types the same)
        if (typeOrderA != typeOrderB) {
          return (typeOrderA < typeOrderB) ? -1 : 1;
        }
        // At this point, both types should be number types.
#if DEBUG
        if (typeOrderA != 0) {
          throw new ArgumentException("doesn't satisfy typeOrderA == 0");
        }
        if (typeOrderB != 0) {
          throw new ArgumentException("doesn't satisfy typeOrderB == 0");
        }
#endif
        int s1 = GetSignInternal(typeA, objA);
        int s2 = GetSignInternal(typeB, objB);
        if (s1 != s2 && s1 != 2 && s2 != 2) {
          // if both types are numbers
          // and their signs are different
          return (s1 < s2) ? -1 : 1;
        }
        if (s1 == 2 && s2 == 2) {
          // both are NaN
          cmp = 0;
        } else if (s1 == 2) {
          // first object is NaN
          return 1;
        } else if (s2 == 2) {
          // second object is NaN
          return -1;
        } else {
          // DebugUtility.Log("a=" + this + " b=" + other);
          if (typeA == CBORObjectTypeExtendedRational) {
            ERational e1 = NumberInterfaces[typeA].AsExtendedRational(objA);
            if (typeB == CBORObjectTypeExtendedDecimal) {
              EDecimal e2 = NumberInterfaces[typeB].AsExtendedDecimal(objB);
              cmp = e1.CompareToDecimal(e2);
            } else {
              EFloat e2 = NumberInterfaces[typeB].AsExtendedFloat(objB);
              cmp = e1.CompareToBinary(e2);
            }
          } else if (typeB == CBORObjectTypeExtendedRational) {
            ERational e2 = NumberInterfaces[typeB].AsExtendedRational(objB);
            if (typeA == CBORObjectTypeExtendedDecimal) {
              EDecimal e1 = NumberInterfaces[typeA].AsExtendedDecimal(objA);
              cmp = e2.CompareToDecimal(e1);
              cmp = -cmp;
            } else {
              EFloat e1 = NumberInterfaces[typeA].AsExtendedFloat(objA);
              cmp = e2.CompareToBinary(e1);
              cmp = -cmp;
            }
          } else if (typeA == CBORObjectTypeExtendedDecimal ||
                    typeB == CBORObjectTypeExtendedDecimal) {
            EDecimal e1 = null;
            EDecimal e2 = null;
            if (typeA == CBORObjectTypeExtendedFloat) {
              var ef1 = (EFloat)objA;
              e2 = (EDecimal)objB;
              cmp = e2.CompareToBinary(ef1);
              cmp = -cmp;
            } else if (typeB == CBORObjectTypeExtendedFloat) {
              var ef1 = (EFloat)objB;
              e2 = (EDecimal)objA;
              cmp = e2.CompareToBinary(ef1);
            } else {
              e1 = NumberInterfaces[typeA].AsExtendedDecimal(objA);
              e2 = NumberInterfaces[typeB].AsExtendedDecimal(objB);
              cmp = e1.CompareTo(e2);
            }
          } else if (typeA == CBORObjectTypeExtendedFloat || typeB ==
                    CBORObjectTypeExtendedFloat ||
                    typeA == CBORObjectTypeDouble || typeB ==
                    CBORObjectTypeDouble ||
                    typeA == CBORObjectTypeSingle || typeB ==
                    CBORObjectTypeSingle) {
            EFloat e1 = NumberInterfaces[typeA].AsExtendedFloat(objA);
            EFloat e2 = NumberInterfaces[typeB].AsExtendedFloat(objB);
            cmp = e1.CompareTo(e2);
          } else {
            EInteger b1 = NumberInterfaces[typeA].AsEInteger(objA);
            EInteger b2 = NumberInterfaces[typeB].AsEInteger(objB);
            cmp = b1.CompareTo(b2);
          }
        }
      }
      return (cmp == 0) ? ((!this.IsTagged && !other.IsTagged) ? 0 :
           TagsCompare(this.GetAllTags(), other.GetAllTags())) :
                    cmp;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.CompareToIgnoreTags(CBORObject)"]/*'/>
    public int CompareToIgnoreTags(CBORObject other) {
      return (other == null) ? 1 : ((this == other) ? 0 :
                    this.Untag().CompareTo(other.Untag()));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ContainsKey(CBORObject)"]/*'/>
    public bool ContainsKey(CBORObject key) {
      if (key == null) {
        throw new ArgumentNullException(nameof(key));
      }
      if (this.ItemType == CBORObjectTypeMap) {
        IDictionary<CBORObject, CBORObject> map = this.AsMap();
        return map.ContainsKey(key);
      }
      return false;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ContainsKey(System.String)"]/*'/>
    public bool ContainsKey(string key) {
      if (key == null) {
        throw new ArgumentNullException(nameof(key));
      }
      if (this.ItemType == CBORObjectTypeMap) {
        IDictionary<CBORObject, CBORObject> map = this.AsMap();
        return map.ContainsKey(CBORObject.FromObject(key));
      }
      return false;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.EncodeToBytes"]/*'/>
    public byte[] EncodeToBytes() {
      return this.EncodeToBytes(new CBOREncodeOptions(true, true));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.EncodeToBytes(CBOREncodeOptions)"]/*'/>
    public byte[] EncodeToBytes(CBOREncodeOptions options) {
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      if (options.Ctap2Canonical) {
        return CBORCanonical.CtapCanonicalEncode(this);
      }
      // For some types, a memory stream is a lot of
      // overhead since the amount of memory the types
      // use is fixed and small
      var hasComplexTag = false;
      byte tagbyte = 0;
      bool tagged = this.IsTagged;
      if (this.IsTagged) {
        var taggedItem = (CBORObject)this.itemValue;
        if (taggedItem.IsTagged || this.tagHigh != 0 ||
            (this.tagLow >> 16) != 0 || this.tagLow >= 24) {
          hasComplexTag = true;
        } else {
          tagbyte = (byte)(0xc0 + (int)this.tagLow);
        }
      }
      if (!hasComplexTag) {
        switch (this.ItemType) {
          case CBORObjectTypeTextString: {
              byte[] ret = GetOptimizedBytesIfShortAscii(
                this.AsString(), tagged ? (((int)tagbyte) & 0xff) : -1);
              if (ret != null) {
                return ret;
              }
              break;
            }
          case CBORObjectTypeSimpleValue: {
              if (tagged) {
                if (this.IsFalse) {
                  return new[] { tagbyte, (byte)0xf4 };
                }
                if (this.IsTrue) {
                  return new[] { tagbyte, (byte)0xf5 };
                }
                if (this.IsNull) {
                  return new[] { tagbyte, (byte)0xf6 };
                }
                if (this.IsUndefined) {
                  return new[] { tagbyte, (byte)0xf7 };
                }
              } else {
                if (this.IsFalse) {
                  return new[] { (byte)0xf4 };
                }
                if (this.IsTrue) {
                  return new[] { (byte)0xf5 };
                }
                if (this.IsNull) {
                  return new[] { (byte)0xf6 };
                }
                if (this.IsUndefined) {
                  return new[] { (byte)0xf7 };
                }
              }
              break;
            }
          case CBORObjectTypeInteger: {
              var value = (long)this.ThisItem;
              byte[] intBytes = null;
              if (value >= 0) {
                intBytes = GetPositiveInt64Bytes(0, value);
              } else {
                ++value;
                value = -value;  // Will never overflow
                intBytes = GetPositiveInt64Bytes(1, value);
              }
              if (!tagged) {
                return intBytes;
              }
              var ret2 = new byte[intBytes.Length + 1];
              Array.Copy(intBytes, 0, ret2, 1, intBytes.Length);
              ret2[0] = tagbyte;
              return ret2;
            }
          case CBORObjectTypeSingle: {
              var value = (float)this.ThisItem;
              int bits = BitConverter.ToInt32(BitConverter.GetBytes(value), 0);
              return tagged ? new[] { tagbyte, (byte)0xfa,
                (byte)((bits >> 24) & 0xff), (byte)((bits >> 16) & 0xff),
                (byte)((bits >> 8) & 0xff), (byte)(bits & 0xff) } :
                new[] { (byte)0xfa, (byte)((bits >> 24) & 0xff),
                (byte)((bits >> 16) & 0xff), (byte)((bits >> 8) & 0xff),
                (byte)(bits & 0xff) };
            }
          case CBORObjectTypeDouble: {
              var value = (double)this.ThisItem;
              long bits = BitConverter.ToInt64(BitConverter.GetBytes(value), 0);
              return tagged ? new[] { tagbyte, (byte)0xfb,
                (byte)((bits >> 56) & 0xff), (byte)((bits >> 48) & 0xff),
                (byte)((bits >> 40) & 0xff), (byte)((bits >> 32) & 0xff),
                (byte)((bits >> 24) & 0xff), (byte)((bits >> 16) & 0xff),
                (byte)((bits >> 8) & 0xff), (byte)(bits & 0xff) } :
                new[] { (byte)0xfb, (byte)((bits >> 56) & 0xff),
                (byte)((bits >> 48) & 0xff), (byte)((bits >> 40) & 0xff),
                (byte)((bits >> 32) & 0xff), (byte)((bits >> 24) & 0xff),
                (byte)((bits >> 16) & 0xff), (byte)((bits >> 8) & 0xff),
                (byte)(bits & 0xff) };
            }
        }
      }
      try {
        using (var ms = new MemoryStream(16)) {
          this.WriteTo(ms, options);
          return ms.ToArray();
        }
      } catch (IOException ex) {
        throw new CBORException("I/O Error occurred", ex);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Equals(System.Object)"]/*'/>
    public override bool Equals(object obj) {
      return this.Equals(obj as CBORObject);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Equals(CBORObject)"]/*'/>
    public bool Equals(CBORObject other) {
      var otherValue = other as CBORObject;
      if (otherValue == null) {
        return false;
      }
      if (this == otherValue) {
        return true;
      }
      switch (this.itemtypeValue) {
        case CBORObjectTypeByteString:
          if (!CBORUtilities.ByteArrayEquals(
            (byte[])this.ThisItem,
            otherValue.itemValue as byte[])) {
            return false;
          }
          break;
        case CBORObjectTypeMap: {
            IDictionary<CBORObject, CBORObject> cbordict =
              otherValue.itemValue as IDictionary<CBORObject, CBORObject>;
            if (!CBORMapEquals(this.AsMap(), cbordict)) {
              return false;
            }
            break;
          }
        case CBORObjectTypeArray:
          if (!CBORArrayEquals(
            this.AsList(),
            otherValue.itemValue as IList<CBORObject>)) {
            return false;
          }
          break;
        default:
          if (!Object.Equals(this.itemValue, otherValue.itemValue)) {
            return false;
          }
          break;
      }
      return this.itemtypeValue == otherValue.itemtypeValue &&
        this.tagLow == otherValue.tagLow && this.tagHigh == otherValue.tagHigh;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.GetByteString"]/*'/>
    public byte[] GetByteString() {
      if (this.ItemType == CBORObjectTypeByteString) {
        return (byte[])this.ThisItem;
      }
      throw new InvalidOperationException("Not a byte string");
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.GetHashCode"]/*'/>
    public override int GetHashCode() {
      var hashCode = 651869431;
      unchecked {
        if (this.itemValue != null) {
          var itemHashCode = 0;
          long longValue = 0L;
          switch (this.itemtypeValue) {
            case CBORObjectTypeByteString:
              itemHashCode =
                CBORUtilities.ByteArrayHashCode((byte[])this.ThisItem);
              break;
            case CBORObjectTypeMap:
              itemHashCode = CBORMapHashCode(this.AsMap());
              break;
            case CBORObjectTypeArray:
              itemHashCode = CBORArrayHashCode(this.AsList());
              break;
            case CBORObjectTypeTextString:
              itemHashCode = StringHashCode((string)this.itemValue);
              break;
            case CBORObjectTypeSimpleValue:
              itemHashCode = (int)this.itemValue;
              break;
            case CBORObjectTypeSingle:
              itemHashCode =
  BitConverter.ToInt32(BitConverter.GetBytes((float)this.itemValue), 0);
              break;
            case CBORObjectTypeDouble:
              longValue =
  BitConverter.ToInt64(BitConverter.GetBytes((double)this.itemValue), 0);
              longValue |= longValue >> 32;
              itemHashCode = unchecked((int)longValue);
              break;
            case CBORObjectTypeInteger:
              longValue = (long)this.itemValue;
              longValue |= longValue >> 32;
              itemHashCode = unchecked((int)longValue);
              break;
            default:
              // EInteger, EFloat, EDecimal, ERational, CBORObject
              itemHashCode = this.itemValue.GetHashCode();
              break;
          }
          hashCode += 651869479 * itemHashCode;
        }
        hashCode += 651869483 * (this.itemtypeValue +
                    this.tagLow + this.tagHigh);
      }
      return hashCode;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.GetTags"]/*'/>
    [Obsolete("Use the GetAllTags method instead.")]
    public BigInteger[] GetTags() {
      EInteger[] etags = this.GetAllTags();
      if (etags.Length == 0) {
        return new BigInteger[0];
      }
      var bigret = new BigInteger[etags.Length];
      for (var i = 0; i < bigret.Length; ++i) {
        bigret[i] = PropertyMap.ToLegacy(etags[i]);
      }
      return bigret;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.GetAllTags"]/*'/>
    public EInteger[] GetAllTags() {
      if (!this.IsTagged) {
        return ValueEmptyTags;
      }
      CBORObject curitem = this;
      if (curitem.IsTagged) {
        var list = new List<EInteger>();
        while (curitem.IsTagged) {
          list.Add(
            LowHighToEInteger(
              curitem.tagLow,
              curitem.tagHigh));
          curitem = (CBORObject)curitem.itemValue;
        }
        return (EInteger[])list.ToArray();
      }
      return new[] { LowHighToEInteger(this.tagLow, this.tagHigh) };
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.HasTag(System.Int32)"]/*'/>
 public bool HasMostOuterTag(int tagValue) {
      if (tagValue < 0) {
        throw new ArgumentException("tagValue (" + tagValue +
                    ") is less than 0");
      }
 return this.IsTagged && this.tagHigh == 0 && this.tagLow == tagValue;
 }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.HasTag(PeterO.BigInteger)"]/*'/>
 public bool HasMostOuterTag(EInteger bigTagValue) {
    if (bigTagValue == null) {
  throw new ArgumentNullException(nameof(bigTagValue));
}
      if (bigTagValue.Sign < 0) {
        throw new ArgumentException("bigTagValue (" + bigTagValue +
                    ") is less than 0");
      }
 return (!this.IsTagged) ? false : this.MostOuterTag.Equals(bigTagValue);
 }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.HasTag(System.Int32)"]/*'/>
    public bool HasTag(int tagValue) {
      if (tagValue < 0) {
        throw new ArgumentException("tagValue (" + tagValue +
                    ") is less than 0");
      }
      CBORObject obj = this;
      while (true) {
        if (!obj.IsTagged) {
          return false;
        }
        if (obj.tagHigh == 0 && tagValue == obj.tagLow) {
          return true;
        }
        obj = (CBORObject)obj.itemValue;
#if DEBUG
        if (obj == null) {
          throw new ArgumentNullException(nameof(tagValue));
        }
#endif
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.HasTag(PeterO.BigInteger)"]/*'/>
    [Obsolete("Use the EInteger version of this method.")]
    public bool HasTag(BigInteger bigTagValue) {
      if (bigTagValue == null) {
        throw new ArgumentNullException(nameof(bigTagValue));
      }
      return this.HasTag(EInteger.FromBytes(
        bigTagValue.toBytes(true),
        true));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.HasTag(PeterO.Numbers.EInteger)"]/*'/>
    public bool HasTag(EInteger bigTagValue) {
      if (bigTagValue == null) {
        throw new ArgumentNullException(nameof(bigTagValue));
      }
      if (bigTagValue.Sign < 0) {
        throw new ArgumentException("doesn't satisfy bigTagValue.Sign>= 0");
      }
      EInteger[] bigTags = this.GetAllTags();
      foreach (EInteger bigTag in bigTags) {
        if (bigTagValue.Equals(bigTag)) {
          return true;
        }
      }
      return false;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Insert(System.Int32,System.Object)"]/*'/>
    public CBORObject Insert(int index, object valueOb) {
      if (this.ItemType == CBORObjectTypeArray) {
        CBORObject mapValue;
        IList<CBORObject> list = this.AsList();
        if (index < 0 || index > list.Count) {
          throw new ArgumentException("index");
        }
        if (valueOb == null) {
          mapValue = CBORObject.Null;
        } else {
          mapValue = valueOb as CBORObject;
          mapValue = mapValue ?? CBORObject.FromObject(valueOb);
        }
        list.Insert(index, mapValue);
      } else {
        throw new InvalidOperationException("Not an array");
      }
      return this;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.IsInfinity"]/*'/>
    public bool IsInfinity() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      return cn != null && cn.IsInfinity(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.IsNaN"]/*'/>
    public bool IsNaN() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      return cn != null && cn.IsNaN(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.IsNegativeInfinity"]/*'/>
    public bool IsNegativeInfinity() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      return cn != null && cn.IsNegativeInfinity(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.IsPositiveInfinity"]/*'/>
    public bool IsPositiveInfinity() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      return cn != null && cn.IsPositiveInfinity(this.ThisItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Negate"]/*'/>
    public CBORObject Negate() {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("This object is not a number.");
      }
      object newItem = cn.Negate(this.ThisItem);
      if (newItem is EDecimal) {
        return CBORObject.FromObject((EDecimal)newItem);
      }
      if (newItem is EInteger) {
        return CBORObject.FromObject((EInteger)newItem);
      }
      if (newItem is EFloat) {
        return CBORObject.FromObject((EFloat)newItem);
      }
      var rat = newItem as ERational;
      return (rat != null) ? CBORObject.FromObject(rat) :
        CBORObject.FromObject(newItem);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Clear"]/*'/>
    public void Clear() {
      if (this.ItemType == CBORObjectTypeArray) {
        IList<CBORObject> list = this.AsList();
        list.Clear();
      } else if (this.ItemType == CBORObjectTypeMap) {
        IDictionary<CBORObject, CBORObject> dict = this.AsMap();
        dict.Clear();
      } else {
        throw new InvalidOperationException("Not a map or array");
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Remove(System.Object)"]/*'/>
    public bool Remove(object obj) {
      if (obj == null) {
        throw new ArgumentNullException(nameof(obj));
      }
      // TODO: Convert null to CBORObject.Null in next major version
      return this.Remove(CBORObject.FromObject(obj));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.RemoveAt(System.Int32)"]/*'/>
    public bool RemoveAt(int index) {
      if (this.ItemType != CBORObjectTypeArray) {
        throw new InvalidOperationException("Not an array");
      }
      if (index < 0 || index >= this.Count) {
        return false;
      }
      IList<CBORObject> list = this.AsList();
      list.RemoveAt(index);
      return true;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Remove(CBORObject)"]/*'/>
    public bool Remove(CBORObject obj) {
      if (obj == null) {
        throw new ArgumentNullException(nameof(obj));
      }
      if (this.ItemType == CBORObjectTypeMap) {
        IDictionary<CBORObject, CBORObject> dict = this.AsMap();
        bool hasKey = dict.ContainsKey(obj);
        if (hasKey) {
          dict.Remove(obj);
          return true;
        }
        return false;
      }
      if (this.ItemType == CBORObjectTypeArray) {
        IList<CBORObject> list = this.AsList();
        return list.Remove(obj);
      }
      throw new InvalidOperationException("Not a map or array");
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Set(System.Object,System.Object)"]/*'/>
    public CBORObject Set(object key, object valueOb) {
      if (this.ItemType == CBORObjectTypeMap) {
        CBORObject mapKey;
        CBORObject mapValue;
        if (key == null) {
          mapKey = CBORObject.Null;
        } else {
          mapKey = key as CBORObject;
          mapKey = mapKey ?? CBORObject.FromObject(key);
        }
        if (valueOb == null) {
          mapValue = CBORObject.Null;
        } else {
          mapValue = valueOb as CBORObject;
          mapValue = mapValue ?? CBORObject.FromObject(valueOb);
        }
        IDictionary<CBORObject, CBORObject> map = this.AsMap();
        if (map.ContainsKey(mapKey)) {
          map[mapKey] = mapValue;
        } else {
          map.Add(mapKey, mapValue);
        }
      } else {
        throw new InvalidOperationException("Not a map");
      }
      return this;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToJSONString"]/*'/>
    public string ToJSONString() {
      return this.ToJSONString(JSONOptions.Default);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToJSONString(JSONOptions)"]/*'/>
    public string ToJSONString(JSONOptions options) {
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      int type = this.ItemType;
      switch (type) {
        case CBORObjectTypeSimpleValue: {
            return this.IsTrue ? "true" : (this.IsFalse ? "false" : "null");
          }
        case CBORObjectTypeInteger: {
            return CBORUtilities.LongToString((long)this.ThisItem);
          }
        default: {
            var sb = new StringBuilder();
            try {
              CBORJson.WriteJSONToInternal(this, new StringOutput(sb), options);
            } catch (IOException ex) {
              // This is truly exceptional
              throw new InvalidOperationException("Internal error", ex);
            }
            return sb.ToString();
          }
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.ToString"]/*'/>
    public override string ToString() {
      StringBuilder sb = null;
      string simvalue = null;
      int type = this.ItemType;
      if (this.IsTagged) {
        if (sb == null) {
          if (type == CBORObjectTypeTextString) {
            // The default capacity of StringBuilder may be too small
            // for many strings, so set a suggested capacity
            // explicitly
            string str = this.AsString();
            sb = new StringBuilder(Math.Min(str.Length, 4096) + 16);
          } else {
            sb = new StringBuilder();
          }
        }
        this.AppendOpeningTags(sb);
      }
      switch (type) {
        case CBORObjectTypeSimpleValue: {
            if (this.IsTrue) {
              simvalue = "true";
              if (sb == null) {
                return simvalue;
              }
              sb.Append(simvalue);
            } else if (this.IsFalse) {
              simvalue = "false";
              if (sb == null) {
                return simvalue;
              }
              sb.Append(simvalue);
            } else if (this.IsNull) {
              simvalue = "null";
              if (sb == null) {
                return simvalue;
              }
              sb.Append(simvalue);
            } else if (this.IsUndefined) {
              simvalue = "undefined";
              if (sb == null) {
                return simvalue;
              }
              sb.Append(simvalue);
            } else {
              sb = sb ?? (new StringBuilder());
              sb.Append("simple(");
              var thisItemInt = (int)this.ThisItem;
              sb.Append(
                CBORUtilities.LongToString(thisItemInt));
              sb.Append(")");
            }

            break;
          }
        case CBORObjectTypeSingle: {
            var f = (float)this.ThisItem;
            simvalue = Single.IsNegativeInfinity(f) ? "-Infinity" :
              (Single.IsPositiveInfinity(f) ? "Infinity" : (Single.IsNaN(f) ?
                    "NaN" : TrimDotZero(CBORUtilities.SingleToString(f))));
            if (sb == null) {
              return simvalue;
            }
            sb.Append(simvalue);
            break;
          }
        case CBORObjectTypeDouble: {
            var f = (double)this.ThisItem;
            simvalue = Double.IsNegativeInfinity(f) ? "-Infinity" :
              (Double.IsPositiveInfinity(f) ? "Infinity" : (Double.IsNaN(f) ?
                    "NaN" : TrimDotZero(CBORUtilities.DoubleToString(f))));
            if (sb == null) {
              return simvalue;
            }
            sb.Append(simvalue);
            break;
          }
        case CBORObjectTypeExtendedFloat: {
            simvalue = ExtendedToString((EFloat)this.ThisItem);
            if (sb == null) {
              return simvalue;
            }
            sb.Append(simvalue);
            break;
          }
        case CBORObjectTypeInteger: {
            var v = (long)this.ThisItem;
            simvalue = CBORUtilities.LongToString(v);
            if (sb == null) {
              return simvalue;
            }
            sb.Append(simvalue);
            break;
          }
        case CBORObjectTypeBigInteger: {
            simvalue = ((EInteger)this.ThisItem).ToString();
            if (sb == null) {
              return simvalue;
            }
            sb.Append(simvalue);
            break;
          }
        case CBORObjectTypeByteString: {
            sb = sb ?? (new StringBuilder());
            sb.Append("h'");
            CBORUtilities.ToBase16(sb, (byte[])this.ThisItem);
            sb.Append("'");
            break;
          }
        case CBORObjectTypeTextString: {
            if (sb == null) {
              return "\"" + this.AsString() + "\"";
            }
            sb.Append('\"');
            sb.Append(this.AsString());
            sb.Append('\"');
            break;
          }
        case CBORObjectTypeArray: {
            sb = sb ?? (new StringBuilder());
            var first = true;
            sb.Append("[");
            foreach (CBORObject i in this.AsList()) {
              if (!first) {
                sb.Append(", ");
              }
              sb.Append(i.ToString());
              first = false;
            }
            sb.Append("]");
            break;
          }
        case CBORObjectTypeMap: {
            sb = sb ?? (new StringBuilder());
            var first = true;
            sb.Append("{");
            IDictionary<CBORObject, CBORObject> map = this.AsMap();
            foreach (KeyValuePair<CBORObject, CBORObject> entry in map) {
              CBORObject key = entry.Key;
              CBORObject value = entry.Value;
              if (!first) {
                sb.Append(", ");
              }
              sb.Append(key.ToString());
              sb.Append(": ");
              sb.Append(value.ToString());
              first = false;
            }
            sb.Append("}");
            break;
          }
        default: {
            if (sb == null) {
              return this.ThisItem.ToString();
            }
            sb.Append(this.ThisItem.ToString());
            break;
          }
      }

      if (this.IsTagged) {
        this.AppendClosingTags(sb);
      }
      return sb.ToString();
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.Untag"]/*'/>
    public CBORObject Untag() {
      CBORObject curobject = this;
      while (curobject.itemtypeValue == CBORObjectTypeTagged) {
        curobject = (CBORObject)curobject.itemValue;
      }
      return curobject;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.UntagOne"]/*'/>
    public CBORObject UntagOne() {
      return (this.itemtypeValue == CBORObjectTypeTagged) ?
        ((CBORObject)this.itemValue) : this;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.WriteJSONTo(System.IO.Stream)"]/*'/>
    public void WriteJSONTo(Stream outputStream) {
      if (outputStream == null) {
        throw new ArgumentNullException(nameof(outputStream));
      }
      CBORJson.WriteJSONToInternal(
  this,
  new StringOutput(outputStream),
  JSONOptions.Default);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.WriteJSONTo(System.IO.Stream,JSONOptions)"]/*'/>
    public void WriteJSONTo(Stream outputStream, JSONOptions options) {
      if (outputStream == null) {
        throw new ArgumentNullException(nameof(outputStream));
      }
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      CBORJson.WriteJSONToInternal(
  this,
  new StringOutput(outputStream),
  options);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.WriteValue(System.IO.Stream,System.Int32,System.Int64)"]/*'/>
    public static int WriteValue(
     Stream outputStream,
     int majorType,
     long value) {
      if (outputStream == null) {
        throw new ArgumentNullException(nameof(outputStream));
      }
      if (majorType < 0) {
        throw new ArgumentException("majorType (" + majorType +
          ") is less than 0");
      }
      if (majorType > 7) {
        throw new ArgumentException("majorType (" + majorType +
          ") is more than 7");
      }
      if (value < 0) {
        throw new ArgumentException("value (" + value +
          ") is less than 0");
      }
      if (majorType == 7) {
        if (value > 255) {
          throw new ArgumentException("value (" + value +
            ") is more than 255");
        }
        if (value <= 23) {
          outputStream.WriteByte((byte)(0xe0 + (int)value));
          return 1;
        } else if (value < 32) {
     throw new ArgumentException("value is from 24 to 31 and major type is 7");
        } else {
          outputStream.WriteByte((byte)0xf8);
          outputStream.WriteByte((byte)value);
          return 2;
        }
      } else {
        return WritePositiveInt64(majorType, value, outputStream);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.WriteValue(System.IO.Stream,System.Int32,System.Int32)"]/*'/>
    public static int WriteValue(
    Stream outputStream,
    int majorType,
    int value) {
      if (outputStream == null) {
        throw new ArgumentNullException(nameof(outputStream));
      }
      if (majorType < 0) {
        throw new ArgumentException("majorType (" + majorType +
          ") is less than 0");
      }
      if (majorType > 7) {
        throw new ArgumentException("majorType (" + majorType +
          ") is more than 7");
      }
      if (value < 0) {
        throw new ArgumentException("value (" + value +
          ") is less than 0");
      }
      if (majorType == 7) {
        if (value > 255) {
          throw new ArgumentException("value (" + value +
            ") is more than 255");
        }
        if (value <= 23) {
          outputStream.WriteByte((byte)(0xe0 + value));
          return 1;
        } else if (value < 32) {
     throw new ArgumentException("value is from 24 to 31 and major type is 7");
        } else {
          outputStream.WriteByte((byte)0xf8);
          outputStream.WriteByte((byte)value);
          return 2;
        }
      } else {
        return WritePositiveInt(majorType, value, outputStream);
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.WriteValue(System.IO.Stream,System.Int32,PeterO.Numbers.EInteger)"]/*'/>
    public static int WriteValue(
    Stream outputStream,
    int majorType,
    EInteger bigintValue) {
      if (outputStream == null) {
        throw new ArgumentNullException(nameof(outputStream));
      }
      if (bigintValue == null) {
        throw new ArgumentNullException(nameof(bigintValue));
      }
      if (bigintValue.Sign < 0) {
        throw new ArgumentException("tagEInt's sign (" + bigintValue.Sign +
                    ") is less than 0");
      }
      if (bigintValue.CompareTo(UInt64MaxValue) > 0) {
        throw new ArgumentException(
          "tag more than 18446744073709551615 (" + bigintValue + ")");
      }
      if (bigintValue.CompareTo(Int64MaxValue) <= 0) {
        return WriteValue(
    outputStream,
    majorType,
    bigintValue.ToInt64Checked());
      }
      long longVal = bigintValue.ToInt64Unchecked();
      var highbyte = (int)((longVal >> 56) & 0xff);
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
      byte[] bytes = new[] { (byte)(27 | (majorType << 5)), (byte)highbyte,
        (byte)((longVal >> 48) & 0xff), (byte)((longVal >> 40) & 0xff),
        (byte)((longVal >> 32) & 0xff), (byte)((longVal >> 24) & 0xff),
        (byte)((longVal >> 16) & 0xff), (byte)((longVal >> 8) & 0xff),
        (byte)(longVal & 0xff) };
      outputStream.Write(bytes, 0, bytes.Length);
      return bytes.Length;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.WriteTo(System.IO.Stream)"]/*'/>
    public void WriteTo(Stream stream) {
      this.WriteTo(stream, new CBOREncodeOptions(true, true));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORObject.WriteTo(System.IO.Stream,CBOREncodeOptions)"]/*'/>
    public void WriteTo(Stream stream, CBOREncodeOptions options) {
      if (stream == null) {
        throw new ArgumentNullException(nameof(stream));
      }
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      if (options.Ctap2Canonical) {
        byte[] bytes = CBORCanonical.CtapCanonicalEncode(this);
        stream.Write(bytes, 0, bytes.Length);
        return;
      }
      this.WriteTags(stream);
      int type = this.ItemType;
      switch (type) {
        case CBORObjectTypeInteger: {
            Write((long)this.ThisItem, stream);
            break;
          }
        case CBORObjectTypeBigInteger: {
            Write((EInteger)this.ThisItem, stream);
            break;
          }
        case CBORObjectTypeByteString: {
            var arr = (byte[])this.ThisItem;
            WritePositiveInt(
              (this.ItemType == CBORObjectTypeByteString) ? 2 : 3,
              arr.Length,
              stream);
            stream.Write(arr, 0, arr.Length);
            break;
          }
        case CBORObjectTypeTextString: {
            Write((string)this.ThisItem, stream, options);
            break;
          }
        case CBORObjectTypeArray: {
            WriteObjectArray(this.AsList(), stream, options);
            break;
          }
        case CBORObjectTypeExtendedDecimal: {
            var dec = (EDecimal)this.ThisItem;
            Write(dec, stream);
            break;
          }
        case CBORObjectTypeExtendedFloat: {
            var flo = (EFloat)this.ThisItem;
            Write(flo, stream);
            break;
          }
        case CBORObjectTypeExtendedRational: {
            var flo = (ERational)this.ThisItem;
            Write(flo, stream);
            break;
          }
        case CBORObjectTypeMap: {
            WriteObjectMap(this.AsMap(), stream, options);
            break;
          }
        case CBORObjectTypeSimpleValue: {
            var value = (int)this.ThisItem;
            if (value < 24) {
              stream.WriteByte((byte)(0xe0 + value));
            } else {
#if DEBUG
              if (value < 32) {
                throw new ArgumentException("value (" + value +
                    ") is less than " + "32");
              }
#endif

              stream.WriteByte(0xf8);
              stream.WriteByte((byte)value);
            }

            break;
          }
        case CBORObjectTypeSingle: {
            Write((float)this.ThisItem, stream);
            break;
          }
        case CBORObjectTypeDouble: {
            Write((double)this.ThisItem, stream);
            break;
          }
        default: {
            throw new ArgumentException("Unexpected data type");
          }
      }
    }

        #pragma warning disable 618
    internal static ICBORTag FindTagConverter(EInteger bigintTag) {
      if (TagHandlersEmpty()) {
        AddTagHandler((EInteger)2, new CBORTag2());
        AddTagHandler((EInteger)3, new CBORTag3());
        AddTagHandler((EInteger)4, new CBORTag4());
        AddTagHandler((EInteger)5, new CBORTag5());
        AddTagHandler((EInteger)264, new CBORTag4(true));
        AddTagHandler((EInteger)265, new CBORTag5(true));
        AddTagHandler((EInteger)25, new CBORTagUnsigned());
        AddTagHandler((EInteger)29, new CBORTagUnsigned());
        AddTagHandler((EInteger)256, new CBORTagAny());
        AddTagHandler(EInteger.Zero, new CBORTag0());
        AddTagHandler((EInteger)32, new CBORTag32());
        AddTagHandler((EInteger)33, new CBORTagGenericString());
        AddTagHandler((EInteger)34, new CBORTagGenericString());
        AddTagHandler((EInteger)35, new CBORTagGenericString());
        AddTagHandler((EInteger)36, new CBORTagGenericString());
        AddTagHandler((EInteger)37, new CBORTag37());
        AddTagHandler((EInteger)30, new CBORTag30());
      }
      lock (ValueTagHandlers) {
        if (ValueTagHandlers.ContainsKey(bigintTag)) {
          return ValueTagHandlers[bigintTag];
        }
#if DEBUG
        if (bigintTag.Equals((EInteger)2)) {
          throw new InvalidOperationException("Expected valid tag handler");
        }
#endif
        return null;
      }
    }

    internal static ICBORTag FindTagConverterLong(long tagLong) {
      return FindTagConverter((EInteger)tagLong);
    }
        #pragma warning restore 618

    internal static CBORObject FromRaw(string str) {
      return new CBORObject(CBORObjectTypeTextString, str);
    }

    internal static CBORObject FromRaw(IList<CBORObject> list) {
      return new CBORObject(CBORObjectTypeArray, list);
    }

    internal static CBORObject FromRaw(IDictionary<CBORObject, CBORObject>
                    map) {
      return new CBORObject(CBORObjectTypeMap, map);
    }

    internal static int GetExpectedLength(int value) {
      return ValueExpectedLengths[value];
    }

    // Generate a CBOR object for head bytes with fixed length.
    // Note that this function assumes that the length of the data
    // was already checked.
    internal static CBORObject GetFixedLengthObject(
      int firstbyte,
      byte[] data) {
      CBORObject fixedObj = valueFixedObjects[firstbyte];
      if (fixedObj != null) {
        return fixedObj;
      }
      int majortype = firstbyte >> 5;
      if (firstbyte >= 0x61 && firstbyte < 0x78) {
        // text string length 1 to 23
        string s = GetOptimizedStringIfShortAscii(data, 0);
        if (s != null) {
          return new CBORObject(CBORObjectTypeTextString, s);
        }
      }
      if ((firstbyte & 0x1c) == 0x18) {
        // contains 1 to 8 extra bytes of additional information
        long uadditional = 0;
        switch (firstbyte & 0x1f) {
          case 24:
            uadditional = (int)(data[1] & (int)0xff);
            break;
          case 25:
            uadditional = ((long)(data[1] & (long)0xff)) << 8;
            uadditional |= (long)(data[2] & (long)0xff);
            break;
          case 26:
            uadditional = ((long)(data[1] & (long)0xff)) << 24;
            uadditional |= ((long)(data[2] & (long)0xff)) << 16;
            uadditional |= ((long)(data[3] & (long)0xff)) << 8;
            uadditional |= (long)(data[4] & (long)0xff);
            break;
          case 27:
            uadditional = ((long)(data[1] & (long)0xff)) << 56;
            uadditional |= ((long)(data[2] & (long)0xff)) << 48;
            uadditional |= ((long)(data[3] & (long)0xff)) << 40;
            uadditional |= ((long)(data[4] & (long)0xff)) << 32;
            uadditional |= ((long)(data[5] & (long)0xff)) << 24;
            uadditional |= ((long)(data[6] & (long)0xff)) << 16;
            uadditional |= ((long)(data[7] & (long)0xff)) << 8;
            uadditional |= (long)(data[8] & (long)0xff);
            break;
          default:
            throw new CBORException("Unexpected data encountered");
        }
        switch (majortype) {
          case 0:
            if ((uadditional >> 63) == 0) {
              // use only if additional's top bit isn't set
              // (additional is a signed long)
              return new CBORObject(CBORObjectTypeInteger, uadditional);
            } else {
              int low = unchecked((int)((uadditional) & 0xffffffffL));
              int high = unchecked((int)((uadditional >> 32) & 0xffffffffL));
              return FromObject(LowHighToEInteger(low, high));
            }
          case 1:
            if ((uadditional >> 63) == 0) {
              // use only if additional's top bit isn't set
              // (additional is a signed long)
              return new CBORObject(CBORObjectTypeInteger, -1 - uadditional);
            } else {
              int low = unchecked((int)((uadditional) & 0xffffffffL));
              int high = unchecked((int)((uadditional >> 32) & 0xffffffffL));
              EInteger bigintAdditional = LowHighToEInteger(low, high);
              EInteger minusOne = -EInteger.One;
              bigintAdditional = minusOne - (EInteger)bigintAdditional;
              return FromObject(bigintAdditional);
            }
          case 7:
            if (firstbyte == 0xf9) {
              return new CBORObject(
                CBORObjectTypeSingle,
             CBORUtilities.HalfPrecisionToSingle(unchecked((int)uadditional)));
            }
            if (firstbyte == 0xfa) {
              float flt = BitConverter.ToSingle(
                BitConverter.GetBytes((int)unchecked((int)uadditional)),
                0);
              return new CBORObject(
                CBORObjectTypeSingle,
                flt);
            }
            if (firstbyte == 0xfb) {
              double flt = BitConverter.ToDouble(
                BitConverter.GetBytes((long)uadditional),
                0);
              return new CBORObject(
                CBORObjectTypeDouble,
                flt);
            }
            if (firstbyte == 0xf8) {
              if ((int)uadditional < 32) {
                throw new CBORException("Invalid overlong simple value");
              }
              return new CBORObject(
                CBORObjectTypeSimpleValue,
                (int)uadditional);
            }
            throw new CBORException("Unexpected data encountered");
          default: throw new CBORException("Unexpected data encountered");
        }
      }
      if (majortype == 2) {  // short byte string
        var ret = new byte[firstbyte - 0x40];
        Array.Copy(data, 1, ret, 0, firstbyte - 0x40);
        return new CBORObject(CBORObjectTypeByteString, ret);
      }
      if (majortype == 3) {  // short text string
        var ret = new StringBuilder(firstbyte - 0x60);
        DataUtilities.ReadUtf8FromBytes(data, 1, firstbyte - 0x60, ret, false);
        return new CBORObject(CBORObjectTypeTextString, ret.ToString());
      }
      if (firstbyte == 0x80) {
        // empty array
        return FromObject(new List<CBORObject>());
      }
      if (firstbyte == 0xa0) {
        // empty map
        return FromObject(new Dictionary<CBORObject, CBORObject>());
      }
      throw new CBORException("Unexpected data encountered");
    }

    internal static CBORObject GetFixedObject(int value) {
      return valueFixedObjects[value];
    }

    internal static ICBORNumber GetNumberInterface(int type) {
      return NumberInterfaces[type];
    }

    internal static string TrimDotZero(string str) {
      return (str.Length > 2 && str[str.Length - 1] == '0' && str[str.Length
                    - 2] == '.') ? str.Substring(0, str.Length - 2) :
        str;
    }

    internal IList<CBORObject> AsList() {
      return (IList<CBORObject>)this.ThisItem;
    }

    internal IDictionary<CBORObject, CBORObject> AsMap() {
      return (IDictionary<CBORObject, CBORObject>)this.ThisItem;
    }
    /*
    internal void Redefine(CBORObject cbor) {
#if DEBUG
      if (cbor == null) {
        throw new ArgumentNullException(nameof(cbor));
      }
#endif
      this.itemtypeValue = cbor.itemtypeValue;
      this.tagLow = cbor.tagLow;
      this.tagHigh = cbor.tagHigh;
      this.itemValue = cbor.itemValue;
    } */

    private static bool BigIntFits(EInteger bigint) {
      return bigint.GetSignedBitLength() <= 64;
    }

    private static bool CBORArrayEquals(
      IList<CBORObject> listA,
      IList<CBORObject> listB) {
      if (listA == null) {
        return listB == null;
      }
      if (listB == null) {
        return false;
      }
      int listACount = listA.Count;
      int listBCount = listB.Count;
      if (listACount != listBCount) {
        return false;
      }
      for (var i = 0; i < listACount; ++i) {
        CBORObject itemA = listA[i];
        CBORObject itemB = listB[i];
        if (!(itemA == null ? itemB == null : itemA.Equals(itemB))) {
          return false;
        }
      }
      return true;
    }

    private static int CBORArrayHashCode(IList<CBORObject> list) {
      if (list == null) {
        return 0;
      }
      var ret = 19;
      int count = list.Count;
      unchecked {
        ret = (ret * 31) + count;
        for (var i = 0; i < count; ++i) {
          ret = (ret * 31) + list[i].GetHashCode();
        }
      }
      return ret;
    }

    private static int StringHashCode(string str) {
      if (str == null) {
        return 0;
      }
      var ret = 19;
      int count = str.Length;
      unchecked {
        ret = (ret * 31) + count;
        for (var i = 0; i < count; ++i) {
          ret = (ret * 31) + (int)str[i];
        }
      }
      return ret;
    }

    private static bool CBORMapEquals(
      IDictionary<CBORObject, CBORObject> mapA,
      IDictionary<CBORObject, CBORObject> mapB) {
      if (mapA == null) {
        return mapB == null;
      }
      if (mapB == null) {
        return false;
      }
      if (mapA.Count != mapB.Count) {
        return false;
      }
      foreach (KeyValuePair<CBORObject, CBORObject> kvp in mapA) {
        CBORObject valueB = null;
        bool hasKey = mapB.TryGetValue(kvp.Key, out valueB);
        if (hasKey) {
          CBORObject valueA = kvp.Value;
          if (!(valueA == null ? valueB == null : valueA.Equals(valueB))) {
            return false;
          }
        } else {
          return false;
        }
      }
      return true;
    }

    private static int CBORMapHashCode(IDictionary<CBORObject, CBORObject> a) {
      // To simplify matters, we use just the count of
      // the map as the basis for the hash code. More complicated
      // hash code calculation would generally involve defining
      // how CBORObjects ought to be compared (since a stable
      // sort order is necessary for two equal maps to have the
      // same hash code), which is much too difficult to do.
      return unchecked(a.Count.GetHashCode() * 19);
    }

    private static void CheckCBORLength(
      long expectedLength,
      long actualLength) {
      if (actualLength < expectedLength) {
        throw new CBORException("Premature end of data");
      }
      if (actualLength > expectedLength) {
        throw new CBORException("Too many bytes");
      }
    }

    private static void CheckCBORLength(int expectedLength, int actualLength) {
      if (actualLength < expectedLength) {
        throw new CBORException("Premature end of data");
      }
      if (actualLength > expectedLength) {
        throw new CBORException("Too many bytes");
      }
    }

    private static CBORObject ConvertWithConverter(object obj) {
#if DEBUG
      if (obj == null) {
        throw new ArgumentNullException(nameof(obj));
      }
#endif
      Object type = obj.GetType();
      ConverterInfo convinfo = null;
      lock (ValueConverters) {
        if (ValueConverters.Count == 0) {
          CBORTag0.AddConverter();
          CBORTag37.AddConverter();
          CBORTag32.AddConverter();
        }
        if (ValueConverters.ContainsKey(type)) {
          convinfo = ValueConverters[type];
        } else {
          return null;
        }
      }
      if (convinfo == null) {
        return null;
      }
      return (CBORObject)PropertyMap.InvokeOneArgumentMethod(
        convinfo.ToObject,
        convinfo.Converter,
        obj);
    }

    private static string ExtendedToString(EFloat ef) {
      if (ef.IsFinite && (ef.Exponent.CompareTo((EInteger)2500) > 0 ||
                    ef.Exponent.CompareTo((EInteger)(-2500)) < 0)) {
        // It can take very long to convert a number with a very high
        // or very low exponent to a decimal string, so do this instead
        return ef.Mantissa + "p" + ef.Exponent;
      }
      return ef.ToString();
    }

    [Obsolete]
    private static ICBORTag FindTagConverter(int tag) {
      return FindTagConverter((EInteger)tag);
    }

    private static byte[] GetOptimizedBytesIfShortAscii(
      string str,
      int tagbyteInt) {
      byte[] bytes;
      if (str.Length <= 255) {
        // The strings will usually be short ASCII strings, so
        // use this optimization
        var offset = 0;
        int length = str.Length;
        int extra = (length < 24) ? 1 : 2;
        if (tagbyteInt >= 0) {
          ++extra;
        }
        bytes = new byte[length + extra];
        if (tagbyteInt >= 0) {
          bytes[offset] = (byte)tagbyteInt;
          ++offset;
        }
        if (length < 24) {
          bytes[offset] = (byte)(0x60 + str.Length);
          ++offset;
        } else {
          bytes[offset] = (byte)0x78;
          bytes[offset + 1] = (byte)str.Length;
          offset += 2;
        }
        var issimple = true;
        for (var i = 0; i < str.Length; ++i) {
          char c = str[i];
          if (c >= 0x80) {
            issimple = false;
            break;
          }
          bytes[i + offset] = unchecked((byte)c);
        }
        if (issimple) {
          return bytes;
        }
      }
      return null;
    }

    private static string GetOptimizedStringIfShortAscii(
      byte[] data,
      int offset) {
      int length = data.Length;
      if (length > offset) {
        var nextbyte = (int)(data[offset] & (int)0xff);
        if (nextbyte >= 0x60 && nextbyte < 0x78) {
          int offsetp1 = 1 + offset;
          // Check for type 3 string of short length
          int rightLength = offsetp1 + (nextbyte - 0x60);
          CheckCBORLength(rightLength, length);
          // Check for all ASCII text
          for (int i = offsetp1; i < length; ++i) {
            if ((data[i] & ((byte)0x80)) != 0) {
              return null;
            }
          }
          // All ASCII text, so convert to a string
          // from a char array without having to
          // convert from UTF-8 first
          var c = new char[length - offsetp1];
          for (int i = offsetp1; i < length; ++i) {
            c[i - offsetp1] = (char)(data[i] & (int)0xff);
          }
          return new String(c);
        }
      }
      return null;
    }

    private static byte[] GetPositiveInt64Bytes(int type, long value) {
      if (value < 0) {
        throw new ArgumentException("value (" + value + ") is less than " +
                    "0");
      }
      if (value < 24) {
        return new[] { (byte)((byte)value | (byte)(type << 5)) };
      }
      if (value <= 0xffL) {
        return new[] { (byte)(24 | (type << 5)), (byte)(value & 0xff)
        };
      }
      if (value <= 0xffffL) {
        return new[] { (byte)(25 | (type << 5)),
          (byte)((value >> 8) & 0xff), (byte)(value & 0xff)
        };
      }
      if (value <= 0xffffffffL) {
        return new[] { (byte)(26 | (type << 5)),
          (byte)((value >> 24) & 0xff), (byte)((value >> 16) & 0xff),
          (byte)((value >> 8) & 0xff), (byte)(value & 0xff)
        };
      }
      return new[] { (byte)(27 | (type << 5)), (byte)((value >> 56) & 0xff),
        (byte)((value >> 48) & 0xff), (byte)((value >> 40) & 0xff),
        (byte)((value >> 32) & 0xff), (byte)((value >> 24) & 0xff),
        (byte)((value >> 16) & 0xff), (byte)((value >> 8) & 0xff),
        (byte)(value & 0xff) };
    }

    private static byte[] GetPositiveIntBytes(int type, int value) {
      if (value < 0) {
        throw new ArgumentException("value (" + value + ") is less than " +
                    "0");
      }
      if (value < 24) {
        return new[] { (byte)((byte)value | (byte)(type << 5)) };
      }
      if (value <= 0xff) {
        return new[] { (byte)(24 | (type << 5)), (byte)(value & 0xff)
        };
      }
      if (value <= 0xffff) {
        return new[] { (byte)(25 | (type << 5)),
          (byte)((value >> 8) & 0xff), (byte)(value & 0xff)
        };
      }
      return new[] { (byte)(26 | (type << 5)), (byte)((value >> 24) & 0xff),
        (byte)((value >> 16) & 0xff), (byte)((value >> 8) & 0xff),
        (byte)(value & 0xff) };
    }

    private static int GetSignInternal(int type, object obj) {
      ICBORNumber cn = NumberInterfaces[type];
      return cn == null ? 2 : cn.Sign(obj);
    }
    // Initialize fixed values for certain
    // head bytes
    private static CBORObject[] InitializeFixedObjects() {
      valueFixedObjects = new CBORObject[256];
      for (var i = 0; i < 0x18; ++i) {
        valueFixedObjects[i] = new CBORObject(CBORObjectTypeInteger, (long)i);
      }
      for (int i = 0x20; i < 0x38; ++i) {
        valueFixedObjects[i] = new CBORObject(
          CBORObjectTypeInteger,
          (long)(-1 - (i - 0x20)));
      }
      valueFixedObjects[0x60] = new CBORObject(
        CBORObjectTypeTextString,
        String.Empty);
      for (int i = 0xe0; i < 0xf8; ++i) {
        valueFixedObjects[i] = new CBORObject(
          CBORObjectTypeSimpleValue,
          (int)(i - 0xe0));
      }
      return valueFixedObjects;
    }

    private static int ListCompare(
      IList<CBORObject> listA,
      IList<CBORObject> listB) {
      if (listA == null) {
        return (listB == null) ? 0 : -1;
      }
      if (listB == null) {
        return 1;
      }
      int listACount = listA.Count;
      int listBCount = listB.Count;
      int c = Math.Min(listACount, listBCount);
      for (var i = 0; i < c; ++i) {
        int cmp = listA[i].CompareTo(listB[i]);
        if (cmp != 0) {
          return cmp;
        }
      }
      return (listACount != listBCount) ? ((listACount < listBCount) ? -1 : 1) :
        0;
    }

    private static EInteger LowHighToEInteger(int tagLow, int tagHigh) {
      byte[] uabytes = null;
      if (tagHigh != 0) {
        uabytes = new byte[9];
        uabytes[7] = (byte)((tagHigh >> 24) & 0xff);
        uabytes[6] = (byte)((tagHigh >> 16) & 0xff);
        uabytes[5] = (byte)((tagHigh >> 8) & 0xff);
        uabytes[4] = (byte)(tagHigh & 0xff);
        uabytes[3] = (byte)((tagLow >> 24) & 0xff);
        uabytes[2] = (byte)((tagLow >> 16) & 0xff);
        uabytes[1] = (byte)((tagLow >> 8) & 0xff);
        uabytes[0] = (byte)(tagLow & 0xff);
        uabytes[8] = 0;
        return EInteger.FromBytes(uabytes, true);
      }
      if (tagLow != 0) {
        uabytes = new byte[5];
        uabytes[3] = (byte)((tagLow >> 24) & 0xff);
        uabytes[2] = (byte)((tagLow >> 16) & 0xff);
        uabytes[1] = (byte)((tagLow >> 8) & 0xff);
        uabytes[0] = (byte)(tagLow & 0xff);
        uabytes[4] = 0;
        return EInteger.FromBytes(uabytes, true);
      }
      return EInteger.Zero;
    }

    private static int MapCompare(
      IDictionary<CBORObject, CBORObject> mapA,
      IDictionary<CBORObject, CBORObject> mapB) {
      if (mapA == null) {
        return (mapB == null) ? 0 : -1;
      }
      if (mapB == null) {
        return 1;
      }
      if (mapA == mapB) {
        return 0;
      }
      int listACount = mapA.Count;
      int listBCount = mapB.Count;
      if (listACount == 0 && listBCount == 0) {
        return 0;
      }
      if (listACount == 0) {
        return -1;
      }
      if (listBCount == 0) {
        return 1;
      }
      var sortedASet = new List<CBORObject>(mapA.Keys);
      var sortedBSet = new List<CBORObject>(mapB.Keys);
      sortedASet.Sort();
      sortedBSet.Sort();
      listACount = sortedASet.Count;
      listBCount = sortedBSet.Count;
      int minCount = Math.Min(listACount, listBCount);
      // Compare the keys
      for (var i = 0; i < minCount; ++i) {
        CBORObject itemA = sortedASet[i];
        CBORObject itemB = sortedBSet[i];
        if (itemA == null) {
          return -1;
        }
        int cmp = itemA.CompareTo(itemB);
        if (cmp != 0) {
          return cmp;
        }
      }
      if (listACount == listBCount) {
        // Both maps have the same keys, so compare their values
        for (var i = 0; i < minCount; ++i) {
          CBORObject keyA = sortedASet[i];
          CBORObject keyB = sortedBSet[i];
          int cmp = mapA[keyA].CompareTo(mapB[keyB]);
          if (cmp != 0) {
            return cmp;
          }
        }
        return 0;
      }
      return (listACount > listBCount) ? 1 : -1;
    }

    private static IList<object> PushObject(
      IList<object> stack,
      object parent,
      object child) {
      if (stack == null) {
        stack = new List<object>();
        stack.Add(parent);
      }
      foreach (object o in stack) {
        if (o == child) {
          throw new ArgumentException("Circular reference in data structure");
        }
      }
      stack.Add(child);
      return stack;
    }

        #pragma warning disable 618
    private static bool TagHandlersEmpty() {
      lock (ValueTagHandlers) {
        return ValueTagHandlers.Count == 0;
      }
    }
        #pragma warning restore 618

    private static int TagsCompare(EInteger[] tagsA, EInteger[] tagsB) {
      if (tagsA == null) {
        return (tagsB == null) ? 0 : -1;
      }
      if (tagsB == null) {
        return 1;
      }
      int listACount = tagsA.Length;
      int listBCount = tagsB.Length;
      int c = Math.Min(listACount, listBCount);
      for (var i = 0; i < c; ++i) {
        int cmp = tagsA[i].CompareTo(tagsB[i]);
        if (cmp != 0) {
          return cmp;
        }
      }
      return (listACount != listBCount) ? ((listACount < listBCount) ? -1 : 1) :
        0;
    }

    private static IList<object> WriteChildObject(
      object parentThisItem,
      CBORObject child,
      Stream outputStream,
      IList<object> stack,
      CBOREncodeOptions options) {
      if (child == null) {
        outputStream.WriteByte(0xf6);
      } else {
        int type = child.ItemType;
        if (type == CBORObjectTypeArray) {
          stack = PushObject(stack, parentThisItem, child.ThisItem);
          child.WriteTags(outputStream);
          WriteObjectArray(child.AsList(), outputStream, stack, options);
          stack.RemoveAt(stack.Count - 1);
        } else if (type == CBORObjectTypeMap) {
          stack = PushObject(stack, parentThisItem, child.ThisItem);
          child.WriteTags(outputStream);
          WriteObjectMap(child.AsMap(), outputStream, stack, options);
          stack.RemoveAt(stack.Count - 1);
        } else {
          child.WriteTo(outputStream, options);
        }
      }
      return stack;
    }

    private static void WriteObjectArray(
      IList<CBORObject> list,
      Stream outputStream,
      CBOREncodeOptions options) {
      WriteObjectArray(list, outputStream, null, options);
    }

    private static void WriteObjectArray(
      IList<CBORObject> list,
      Stream outputStream,
      IList<object> stack,
      CBOREncodeOptions options) {
      object thisObj = list;
      WritePositiveInt(4, list.Count, outputStream);
      foreach (CBORObject i in list) {
        stack = WriteChildObject(thisObj, i, outputStream, stack, options);
      }
    }

    private static void WriteObjectMap(
      IDictionary<CBORObject, CBORObject> map,
      Stream outputStream,
      CBOREncodeOptions options) {
      WriteObjectMap(map, outputStream, null, options);
    }

    private static void WriteObjectMap(
      IDictionary<CBORObject, CBORObject> map,
      Stream outputStream,
      IList<object> stack,
      CBOREncodeOptions options) {
      object thisObj = map;
      WritePositiveInt(5, map.Count, outputStream);
      foreach (KeyValuePair<CBORObject, CBORObject> entry in map) {
        CBORObject key = entry.Key;
        CBORObject value = entry.Value;
        stack = WriteChildObject(
          thisObj,
          key,
          outputStream,
          stack,
          options);
        stack = WriteChildObject(
          thisObj,
          value,
          outputStream,
          stack,
          options);
      }
    }

    private static int WritePositiveInt(int type, int value, Stream s) {
      byte[] bytes = GetPositiveIntBytes(type, value);
      s.Write(bytes, 0, bytes.Length);
      return bytes.Length;
    }

    private static int WritePositiveInt64(int type, long value, Stream s) {
      byte[] bytes = GetPositiveInt64Bytes(type, value);
      s.Write(bytes, 0, bytes.Length);
      return bytes.Length;
    }

    private static void WriteStreamedString(string str, Stream stream) {
      byte[] bytes;
      bytes = GetOptimizedBytesIfShortAscii(str, -1);
      if (bytes != null) {
        stream.Write(bytes, 0, bytes.Length);
        return;
      }
      bytes = new byte[StreamedStringBufferLength];
      var byteIndex = 0;
      var streaming = false;
      for (int index = 0; index < str.Length; ++index) {
        int c = str[index];
        if (c <= 0x7f) {
          if (byteIndex >= StreamedStringBufferLength) {
            // Write bytes retrieved so far
            if (!streaming) {
              stream.WriteByte((byte)0x7f);
            }
            WritePositiveInt(3, byteIndex, stream);
            stream.Write(bytes, 0, byteIndex);
            byteIndex = 0;
            streaming = true;
          }
          bytes[byteIndex++] = (byte)c;
        } else if (c <= 0x7ff) {
          if (byteIndex + 2 > StreamedStringBufferLength) {
            // Write bytes retrieved so far - the next three bytes
            // would exceed the length, and the CBOR spec forbids
            // splitting characters when generating text strings
            if (!streaming) {
              stream.WriteByte((byte)0x7f);
            }
            WritePositiveInt(3, byteIndex, stream);
            stream.Write(bytes, 0, byteIndex);
            byteIndex = 0;
            streaming = true;
          }
          bytes[byteIndex++] = (byte)(0xc0 | ((c >> 6) & 0x1f));
          bytes[byteIndex++] = (byte)(0x80 | (c & 0x3f));
        } else {
          if ((c & 0xfc00) == 0xd800 && index + 1 < str.Length &&
              (str[index + 1] & 0xfc00) == 0xdc00) {
            // Get the Unicode code point for the surrogate pair
            c = 0x10000 + ((c - 0xd800) << 10) + (str[index + 1] - 0xdc00);
            ++index;
          } else if ((c & 0xf800) == 0xd800) {
            // unpaired surrogate, write U + FFFD instead
            c = 0xfffd;
          }
          if (c <= 0xffff) {
            if (byteIndex + 3 > StreamedStringBufferLength) {
              // Write bytes retrieved so far - the next three bytes
              // would exceed the length, and the CBOR spec forbids
              // splitting characters when generating text strings
              if (!streaming) {
                stream.WriteByte((byte)0x7f);
              }
              WritePositiveInt(3, byteIndex, stream);
              stream.Write(bytes, 0, byteIndex);
              byteIndex = 0;
              streaming = true;
            }
            bytes[byteIndex++] = (byte)(0xe0 | ((c >> 12) & 0x0f));
            bytes[byteIndex++] = (byte)(0x80 | ((c >> 6) & 0x3f));
            bytes[byteIndex++] = (byte)(0x80 | (c & 0x3f));
          } else {
            if (byteIndex + 4 > StreamedStringBufferLength) {
              // Write bytes retrieved so far - the next four bytes
              // would exceed the length, and the CBOR spec forbids
              // splitting characters when generating text strings
              if (!streaming) {
                stream.WriteByte((byte)0x7f);
              }
              WritePositiveInt(3, byteIndex, stream);
              stream.Write(bytes, 0, byteIndex);
              byteIndex = 0;
              streaming = true;
            }
            bytes[byteIndex++] = (byte)(0xf0 | ((c >> 18) & 0x07));
            bytes[byteIndex++] = (byte)(0x80 | ((c >> 12) & 0x3f));
            bytes[byteIndex++] = (byte)(0x80 | ((c >> 6) & 0x3f));
            bytes[byteIndex++] = (byte)(0x80 | (c & 0x3f));
          }
        }
      }
      WritePositiveInt(3, byteIndex, stream);
      stream.Write(bytes, 0, byteIndex);
      if (streaming) {
        stream.WriteByte((byte)0xff);
      }
    }

    //-----------------------------------------------------------
    private void AppendClosingTags(StringBuilder sb) {
      CBORObject curobject = this;
      while (curobject.IsTagged) {
        sb.Append(')');
        curobject = (CBORObject)curobject.itemValue;
      }
    }

    private void AppendOpeningTags(StringBuilder sb) {
      CBORObject curobject = this;
      while (curobject.IsTagged) {
        int low = curobject.tagLow;
        int high = curobject.tagHigh;
        if (high == 0 && (low >> 16) == 0) {
          sb.Append(CBORUtilities.LongToString(low));
        } else {
          EInteger bi = LowHighToEInteger(low, high);
          sb.Append(bi.ToString());
        }
        sb.Append('(');
        curobject = (CBORObject)curobject.itemValue;
      }
    }

    private int AsInt32(int minValue, int maxValue) {
      ICBORNumber cn = NumberInterfaces[this.ItemType];
      if (cn == null) {
        throw new InvalidOperationException("not a number type");
      }
      return cn.AsInt32(this.ThisItem, minValue, maxValue);
    }

    private void WriteTags(Stream s) {
      CBORObject curobject = this;
      while (curobject.IsTagged) {
        int low = curobject.tagLow;
        int high = curobject.tagHigh;
        if (high == 0 && (low >> 16) == 0) {
          WritePositiveInt(6, low, s);
        } else if (high == 0) {
          long value = ((long)low) & 0xffffffffL;
          WritePositiveInt64(6, value, s);
        } else if ((high >> 16) == 0) {
          long value = ((long)low) & 0xffffffffL;
          long highValue = ((long)high) & 0xffffffffL;
          value |= highValue << 32;
          WritePositiveInt64(6, value, s);
        } else {
          byte[] arrayToWrite = { (byte)0xdb,
            (byte)((high >> 24) & 0xff), (byte)((high >> 16) & 0xff),
            (byte)((high >> 8) & 0xff), (byte)(high & 0xff),
            (byte)((low >> 24) & 0xff), (byte)((low >> 16) & 0xff),
            (byte)((low >> 8) & 0xff), (byte)(low & 0xff) };
          s.Write(arrayToWrite, 0, 9);
        }
        curobject = (CBORObject)curobject.itemValue;
      }
    }

    private sealed class ConverterInfo {
      private object toObject;

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.ConverterInfo.ToObject"]/*'/>
      public object ToObject {
        get {
          return this.toObject;
        }

        set {
          this.toObject = value;
        }
      }

      private object converter;

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBORObject.ConverterInfo.Converter"]/*'/>
      public object Converter {
        get {
          return this.converter;
        }

        set {
          this.converter = value;
        }
      }
    }
  }
}
