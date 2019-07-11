/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using PeterO;
using PeterO.Numbers;

namespace PeterO.Cbor {
  internal static class PropertyMap2 {
    private sealed class PropertyData {
      private string name;

      public string Name {
        get {
          return this.name;
        }

        set {
          this.name = value;
        }
      }

      private PropertyInfo prop;
#if NET20 || NET40
            public static bool HasUsableGetter(PropertyInfo pi) {
        return pi != null && pi.CanRead && !pi.GetGetMethod().IsStatic &&
                    pi.GetGetMethod().IsPublic;
      }

      public static bool HasUsableSetter(PropertyInfo pi) {
        return pi != null && pi.CanWrite && !pi.GetSetMethod().IsStatic &&
           pi.GetSetMethod().IsPublic;
      }
#else
      public static bool HasUsableGetter(PropertyInfo pi) {
        return pi != null && pi.CanRead && !pi.GetMethod.IsStatic &&
             pi.GetMethod.IsPublic;
      }

      public static bool HasUsableSetter(PropertyInfo pi) {
        return pi != null && pi.CanWrite && !pi.SetMethod.IsStatic &&
             pi.SetMethod.IsPublic;
      }
#endif
      public bool HasUsableGetter() {
        return HasUsableGetter(this.prop);
      }

      public bool HasUsableSetter() {
        return HasUsableSetter(this.prop);
      }

      public string GetAdjustedName(bool useCamelCase) {
        string thisName = this.Name;
        if (useCamelCase) {
          if (CBORUtilities.NameStartsWithWord(thisName, "Is")) {
            thisName = thisName.Substring(2);
          }
          thisName = CBORUtilities.FirstCharLower(thisName);
        } else {
          thisName = CBORUtilities.FirstCharUpper(thisName);
        }
        return thisName;
      }

      public PropertyInfo Prop {
        get {
          return this.prop;
        }

        set {
          this.prop = value;
        }
      }
    }

#if NET40 || NET20
    private static IEnumerable<PropertyInfo> GetTypeProperties(Type t) {
      return t.GetProperties(BindingFlags.Public |
        BindingFlags.Instance);
    }

    private static bool IsAssignableFrom(Type superType, Type subType) {
      return superType.IsAssignableFrom(subType);
    }

    private static MethodInfo GetTypeMethod(
  Type t,
  string name,
  Type[] parameters) {
      return t.GetMethod(name, parameters);
    }

    private static bool HasCustomAttribute(
  Type t,
  string name) {
#if NET40 || NET20
      foreach (var attr in t.GetCustomAttributes(false)) {
#else
    foreach (var attr in t.CustomAttributes) {
#endif
        if (attr.GetType().FullName.Equals(name)) {
          return true;
        }
      }
      return false;
    }
#else
    private static bool IsAssignableFrom(Type superType, Type subType) {
      return superType.GetTypeInfo().IsAssignableFrom(subType.GetTypeInfo());
    }

    private static IEnumerable<PropertyInfo> GetTypeProperties(Type t) {
      return t.GetRuntimeProperties();
    }

    private static MethodInfo GetTypeMethod(
  Type t,
  string name,
  Type[] parameters) {
      return t.GetRuntimeMethod(name, parameters);
    }

    private static bool HasCustomAttribute(
  Type t,
  string name) {
      foreach (var attr in t.GetTypeInfo().GetCustomAttributes()) {
        if (attr.GetType().FullName.Equals(name)) {
          return true;
        }
      }
      return false;
    }

#endif

    private static readonly IDictionary<Type, IList<PropertyData>>
      ValuePropertyLists = new Dictionary<Type, IList<PropertyData>>();

    private static string RemoveIsPrefix(string pn) {
      return CBORUtilities.NameStartsWithWord(pn, "Is") ? pn.Substring(2) : pn;
    }

    private static IList<PropertyData> GetPropertyList(Type t) {
      lock (ValuePropertyLists) {
        if (
 ValuePropertyLists.TryGetValue(
 t,
 out IList<PropertyData> ret)) {
          return ret;
        }
        ret = new List<PropertyData>();
        bool anonymous = HasCustomAttribute(
          t,
          "System.Runtime.CompilerServices.CompilerGeneratedAttribute");
        var names = new Dictionary<string, int>();
        foreach (PropertyInfo pi in GetTypeProperties(t)) {
          var pn = RemoveIsPrefix(pi.Name);
          if (names.ContainsKey(pn)) {
            ++names[pn];
          } else {
            names[pn] = 1;
          }
        }
        foreach (PropertyInfo pi in GetTypeProperties(t)) {
          if (pi.CanRead && (pi.CanWrite || anonymous) &&
          pi.GetIndexParameters().Length == 0) {
            if (PropertyData.HasUsableGetter(pi) ||
                PropertyData.HasUsableSetter(pi)) {
              var pn = RemoveIsPrefix(pi.Name);
              // Ignore ambiguous properties
              if (names.ContainsKey(pn) && names[pn] > 1) {
                continue;
              }
              PropertyData pd = new PropertyMap2.PropertyData() {
                Name = pi.Name,
                Prop = pi
              };
              ret.Add(pd);
            }
          }
        }
        ValuePropertyLists.Add(t, ret);
        return ret;
      }
    }

    public static bool ExceedsKnownLength(Stream inStream, long size) {
      return (inStream is MemoryStream) && (size > (inStream.Length -
        inStream.Position));
    }

    public static void SkipStreamToEnd(Stream inStream) {
      if (inStream is MemoryStream) {
        inStream.Position = inStream.Length;
      }
    }

    public static bool FirstElement(int[] index, int[] dimensions) {
      foreach (var d in dimensions) {
        if (d == 0) {
          return false;
        }
      }
      return true;
    }

    public static bool NextElement(int[] index, int[] dimensions) {
      for (var i = dimensions.Length - 1; i >= 0; --i) {
        if (dimensions[i] > 0) {
          ++index[i];
          if (index[i] >= dimensions[i]) {
            index[i] = 0;
          } else {
            return true;
          }
        }
      }
      return false;
    }

    public static CBORObject BuildCBORArray(int[] dimensions) {
      int zeroPos = dimensions.Length;
      for (var i = 0; i < dimensions.Length; ++i) {
        if (dimensions[i] == 0) {
          {
            zeroPos = i;
          }
          break;
        }
      }
      int arraydims = zeroPos - 1;
      if (arraydims <= 0) {
        return CBORObject.NewArray();
      }
      var stack = new CBORObject[zeroPos];
      var index = new int[zeroPos];
      var stackpos = 0;
      CBORObject ret = CBORObject.NewArray();
      stack[0] = ret;
      index[0] = 0;
      for (var i = 0; i < dimensions[0]; ++i) {
        ret.Add(CBORObject.NewArray());
      }
      ++stackpos;
      while (stackpos > 0) {
        int curindex = index[stackpos - 1];
        if (curindex < stack[stackpos - 1].Count) {
          CBORObject subobj = stack[stackpos - 1][curindex];
          if (stackpos < zeroPos) {
            stack[stackpos] = subobj;
            index[stackpos] = 0;
            for (var i = 0; i < dimensions[stackpos]; ++i) {
              subobj.Add(CBORObject.NewArray());
            }
            ++index[stackpos - 1];
            ++stackpos;
          } else {
            ++index[stackpos - 1];
          }
        } else {
          --stackpos;
        }
      }
      return ret;
    }

    private static CBORObject GetCBORObject(CBORObject cbor, int[] index) {
      CBORObject ret = cbor;
      foreach (var i in index) {
        ret = ret[i];
      }
      return ret;
    }

    private static void SetCBORObject(
  CBORObject cbor,
  int[] index,
  CBORObject obj) {
      CBORObject ret = cbor;
      for (var i = 0; i < index.Length - 1; ++i) {
        ret = ret[index[i]];
      }
      int ilen = index[index.Length - 1];
      while (ilen >= ret.Count) {
        {
          ret.Add(CBORObject.Null);
        }
      }
      ret[ilen] = obj;
    }

    public static Array FillArray(
  Array arr,
  Type elementType,
  CBORObject cbor,
  CBORTypeMapper mapper,
  PODOptions options,
  int depth) {
      int rank = arr.Rank;
      if (rank == 0) {
        return arr;
      }
      if (rank == 1) {
        int len = arr.GetLength(0);
        for (var i = 0; i < len; ++i) {
       object item = cbor[i].ToObject(
  elementType,
  mapper,
  options,
  depth + 1);
          arr.SetValue(item, i);
        }
        return arr;
      }
      var index = new int[rank];
      var dimensions = new int[rank];
      for (var i = 0; i < rank; ++i) {
        dimensions[i] = arr.GetLength(i);
      }
      if (!FirstElement(index, dimensions)) {
        return arr;
      }
      do {
        object item = GetCBORObject(
  cbor,
  index).ToObject(
  elementType,
  mapper,
  options,
  depth + 1);
        arr.SetValue(item, index);
      } while (NextElement(index, dimensions));
      return arr;
    }

    public static int[] GetDimensions(CBORObject obj) {
      if (obj.Type != CBORType.Array) {
        throw new CBORException();
      }
      // Common cases
      if (obj.Count == 0) {
        return new int[] { 0 };
      }
      if (obj[0].Type != CBORType.Array) {
        return new int[] { obj.Count };
      }
      // Complex cases
      var list = new List<int>();
      list.Add(obj.Count);
      while (obj.Type == CBORType.Array &&
            obj.Count > 0 && obj[0].Type == CBORType.Array) {
        list.Add(obj[0].Count);
        obj = obj[0];
      }
      return list.ToArray();
    }

    public static object ObjectToEnum(CBORObject obj, Type enumType) {
      Type utype = Enum.GetUnderlyingType(enumType);
      object ret = null;
      if (obj.Type == CBORType.Number && obj.IsIntegral) {
        ret = Enum.ToObject(enumType, TypeToIntegerObject(obj, utype));
        if (!Enum.IsDefined(enumType, ret)) {
          throw new CBORException("Unrecognized enum value: " +
          obj.ToString());
        }
        return ret;
      } else if (obj.Type == CBORType.TextString) {
        var nameString = obj.AsString();
        foreach (var name in Enum.GetNames(enumType)) {
          if (nameString.Equals(name)) {
            return Enum.Parse(enumType, name);
          }
        }
        throw new CBORException("Not found: " + obj.ToString());
      } else {
        throw new CBORException("Unrecognized enum value: " +
           obj.ToString());
      }
    }

    public static object EnumToObject(Enum value) {
      return value.ToString();
    }

    public static object EnumToObjectAsInteger(Enum value) {
      Type t = Enum.GetUnderlyingType(value.GetType());
      if (t.Equals(typeof(ulong))) {
        ulong uvalue = Convert.ToUInt64(value);
        return EInteger.FromUInt64(uvalue);
      }
      return t.Equals(typeof(long)) ? Convert.ToInt64(value) :
      (t.Equals(typeof(uint)) ? Convert.ToInt64(value) :
      Convert.ToInt32(value));
    }

    public static object FindOneArgumentMethod(
  object obj,
  string name,
  Type argtype) {
      return GetTypeMethod(obj.GetType(), name, new[] { argtype });
    }

    public static object InvokeOneArgumentMethod(
  object methodInfo,
  object obj,
  object argument) {
      return ((MethodInfo)methodInfo).Invoke(obj, new[] { argument });
    }

    public static byte[] UUIDToBytes(Guid guid) {
      var bytes2 = new byte[16];
      var bytes = guid.ToByteArray();
      Array.Copy(bytes, bytes2, 16);
      // Swap the bytes to conform with the UUID RFC
      bytes2[0] = bytes[3];
      bytes2[1] = bytes[2];
      bytes2[2] = bytes[1];
      bytes2[3] = bytes[0];
      bytes2[4] = bytes[5];
      bytes2[5] = bytes[4];
      bytes2[6] = bytes[7];
      bytes2[7] = bytes[6];
      return bytes2;
    }

    private static bool StartsWith(string str, string pfx) {
      return str != null && str.Length >= pfx.Length &&
        str.Substring(0, pfx.Length).Equals(pfx);
    }

    private static object TypeToIntegerObject(CBORObject objThis, Type t) {
      if (t.Equals(typeof(int))) {
        return objThis.AsInt32();
      }
      if (t.Equals(typeof(short))) {
        return objThis.AsInt16();
      }
      if (t.Equals(typeof(ushort))) {
        return objThis.AsUInt16();
      }
      if (t.Equals(typeof(byte))) {
        return objThis.AsByte();
      }
      if (t.Equals(typeof(sbyte))) {
        return objThis.AsSByte();
      }
      if (t.Equals(typeof(long))) {
        return objThis.AsInt64();
      }
      if (t.Equals(typeof(uint))) {
        return objThis.AsUInt32();
      }
      if (t.Equals(typeof(ulong))) {
        return objThis.AsUInt64();
      }
      throw new CBORException("Type not supported");
    }

    public static object TypeToObject(
         CBORObject objThis,
         Type t,
         CBORTypeMapper mapper,
         PODOptions options,
         int depth) {
      if (t.Equals(typeof(int))) {
        return objThis.AsInt32();
      }
      if (t.Equals(typeof(short))) {
        return objThis.AsInt16();
      }
      if (t.Equals(typeof(ushort))) {
        return objThis.AsUInt16();
      }
      if (t.Equals(typeof(byte))) {
        return objThis.AsByte();
      }
      if (t.Equals(typeof(sbyte))) {
        return objThis.AsSByte();
      }
      if (t.Equals(typeof(long))) {
        return objThis.AsInt64();
      }
      if (t.Equals(typeof(uint))) {
        return objThis.AsUInt32();
      }
      if (t.Equals(typeof(ulong))) {
        return objThis.AsUInt64();
      }
      if (t.Equals(typeof(double))) {
        return objThis.AsDouble();
      }
      if (t.Equals(typeof(decimal))) {
        return objThis.AsDecimal();
      }
      if (t.Equals(typeof(float))) {
        return objThis.AsSingle();
      }
      if (t.Equals(typeof(bool))) {
        return objThis.AsBoolean();
      }
      if (t.Equals(typeof(char))) {
if (objThis.Type == CBORType.TextString) {
  string s = objThis.AsString();
  if (s.Length != 1) {
 throw new CBORException("Can't convert to char");
}
  return s[0];
}
if (objThis.IsIntegral && objThis.CanTruncatedIntFitInInt32()) {
  int c = objThis.AsInt32();
  if (c < 0 || c >= 0x10000) {
 throw new CBORException("Can't convert to char");
}
  return (char)c;
}
throw new CBORException("Can't convert to char");
      }
      if (t.Equals(typeof(DateTime))) {
        return new CBORDateConverter().FromCBORObject(objThis);
      }
      if (t.Equals(typeof(Guid))) {
        return new CBORUuidConverter().FromCBORObject(objThis);
      }
      if (t.Equals(typeof(Uri))) {
        return new CBORUriConverter().FromCBORObject(objThis);
      }
      if (t.Equals(typeof(EDecimal))) {
        return objThis.AsEDecimal();
      }
      if (t.Equals(typeof(EFloat))) {
        return objThis.AsEFloat();
      }
      if (t.Equals(typeof(EInteger))) {
        return objThis.AsEInteger();
      }
      if (t.Equals(typeof(ERational))) {
        return objThis.AsERational();
      }
      if (IsAssignableFrom(typeof(Enum), t)) {
        return ObjectToEnum(objThis, t);
      }
      if (objThis.Type == CBORType.ByteString) {
        if (t.Equals(typeof(byte[]))) {
          byte[] bytes = objThis.GetByteString();
          var byteret = new byte[bytes.Length];
          Array.Copy(bytes, 0, byteret, 0, byteret.Length);
          return byteret;
        }
      }
      if (objThis.Type == CBORType.Array) {
        Type objectType = typeof(object);
        var isList = false;
        object listObject = null;
#if NET40 || NET20
    if (IsAssignableFrom(typeof(Array), t)) {
Type elementType = t.GetElementType();
          Array array = Array.CreateInstance(
        elementType,
        GetDimensions(objThis));
    return FillArray(array, elementType, objThis, mapper, options, depth);
        }
        if (t.IsGenericType) {
          Type td = t.GetGenericTypeDefinition();
          isList = td.Equals(typeof(List<>)) || td.Equals(typeof(IList<>)) ||
            td.Equals(typeof(ICollection<>)) ||
            td.Equals(typeof(IEnumerable<>));
        }
        isList = isList && t.GetGenericArguments().Length == 1;
        if (isList) {
          objectType = t.GetGenericArguments()[0];
          Type listType = typeof(List<>).MakeGenericType(objectType);
          listObject = Activator.CreateInstance(listType);
        }
#else
        if (IsAssignableFrom(typeof(Array), t)) {
          Type elementType = t.GetElementType();
          Array array = Array.CreateInstance(
        elementType,
        GetDimensions(objThis));
          return FillArray(array, elementType, objThis, mapper, options, depth);
        }
        if (t.GetTypeInfo().IsGenericType) {
          Type td = t.GetGenericTypeDefinition();
          isList = (td.Equals(typeof(List<>)) ||
  td.Equals(typeof(IList<>)) ||
  td.Equals(typeof(ICollection<>)) ||
  td.Equals(typeof(IEnumerable<>)));
        }
        isList = (isList && t.GenericTypeArguments.Length == 1);
        if (isList) {
          objectType = t.GenericTypeArguments[0];
          Type listType = typeof(List<>).MakeGenericType(objectType);
          listObject = Activator.CreateInstance(listType);
        }
#endif
        if (listObject == null) {
          if (t.Equals(typeof(IList)) ||
            t.Equals(typeof(ICollection)) || t.Equals(typeof(IEnumerable))) {
            listObject = new List<object>();
            objectType = typeof(object);
          }
        }
        if (listObject != null) {
          System.Collections.IList ie = (System.Collections.IList)listObject;
          foreach (CBORObject value in objThis.Values) {
            ie.Add(value.ToObject(objectType, mapper, options, depth + 1));
          }
          return listObject;
        }
      }
      if (objThis.Type == CBORType.Map) {
        var isDict = false;
        Type keyType = null;
        Type valueType = null;
        object dictObject = null;
#if NET40 || NET20
        isDict = t.IsGenericType;
        if (t.IsGenericType) {
          Type td = t.GetGenericTypeDefinition();
          isDict = td.Equals(typeof(Dictionary<,>)) ||
            td.Equals(typeof(IDictionary<,>));
        }
        // DebugUtility.Log("list=" + isDict);
        isDict = isDict && t.GetGenericArguments().Length == 2;
        // DebugUtility.Log("list=" + isDict);
        if (isDict) {
          keyType = t.GetGenericArguments()[0];
          valueType = t.GetGenericArguments()[1];
          Type listType = typeof(Dictionary<,>).MakeGenericType(
            keyType,
            valueType);
          dictObject = Activator.CreateInstance(listType);
        }
#else
        isDict = (t.GetTypeInfo().IsGenericType);
        if (t.GetTypeInfo().IsGenericType) {
          Type td = t.GetGenericTypeDefinition();
          isDict = (td.Equals(typeof(Dictionary<,>)) ||
  td.Equals(typeof(IDictionary<,>)));
        }
        //DebugUtility.Log("list=" + isDict);
        isDict = (isDict && t.GenericTypeArguments.Length == 2);
        //DebugUtility.Log("list=" + isDict);
        if (isDict) {
          keyType = t.GenericTypeArguments[0];
          valueType = t.GenericTypeArguments[1];
          Type listType = typeof(Dictionary<,>).MakeGenericType(
            keyType,
            valueType);
          dictObject = Activator.CreateInstance(listType);
        }
#endif
        if (dictObject == null) {
          if (t.Equals(typeof(IDictionary))) {
            dictObject = new Dictionary<object, object>();
            keyType = typeof(object);
            valueType = typeof(object);
          }
        }
        if (dictObject != null) {
          System.Collections.IDictionary idic =
            (System.Collections.IDictionary)dictObject;
          foreach (CBORObject key in objThis.Keys) {
            CBORObject value = objThis[key];
            idic.Add(
  key.ToObject(keyType, mapper, options, depth + 1),
  value.ToObject(valueType, mapper, options, depth + 1));
          }
          return dictObject;
        }
        if (mapper != null) {
          if (!mapper.FilterTypeName(t.FullName)) {
            throw new CBORException("Type " + t.FullName +
                  " not supported");
          }
        } else {
       if (t.FullName != null && (StartsWith(t.FullName, "Microsoft.Win32."
) ||
             StartsWith(t.FullName, "System.IO."))) {
            throw new CBORException("Type " + t.FullName +
                  " not supported");
          }
          if (StartsWith(t.FullName, "System.") &&
            !HasCustomAttribute(t, "System.SerializableAttribute")) {
            throw new CBORException("Type " + t.FullName +
                  " not supported");
          }
        }
        var values = new List<KeyValuePair<string, CBORObject>>();
        foreach (string key in PropertyMap2.GetPropertyNames(
                   t,
                   options != null ? options.UseCamelCase : true)) {
          if (objThis.ContainsKey(key)) {
            CBORObject cborValue = objThis[key];
            var dict = new KeyValuePair<string, CBORObject>(
              key,
              cborValue);
            values.Add(dict);
          }
        }
        return PropertyMap2.ObjectWithProperties(
    t,
    values,
    mapper,
    options,
    depth);
      } else {
        throw new CBORException();
      }
    }

    public static object ObjectWithProperties(
         Type t,
         IEnumerable<KeyValuePair<string, CBORObject>> keysValues,
       CBORTypeMapper mapper,
       PODOptions options,
 int depth) {
      object o = Activator.CreateInstance(t);
      var dict = new Dictionary<string, CBORObject>();
      foreach (var kv in keysValues) {
        var name = kv.Key;
        dict[name] = kv.Value;
      }
      foreach (PropertyData key in GetPropertyList(o.GetType())) {
        if (!key.HasUsableSetter() || !key.HasUsableGetter()) {
          // Require properties to have both a setter and
          // a getter to be eligible for setting
          continue;
        }
   var name = key.GetAdjustedName(options != null ? options.UseCamelCase :
          true);
        if (dict.ContainsKey(name)) {
          object dobj = dict[name].ToObject(
  key.Prop.PropertyType,
  mapper,
  options,
  depth + 1);
          key.Prop.SetValue(o, dobj, null);
        }
      }
      return o;
    }

    public static IEnumerable<KeyValuePair<string, object>>
    GetProperties(Object o) {
      return GetProperties(o, true);
    }

    public static IEnumerable<string>
    GetPropertyNames(Type t, bool useCamelCase) {
      foreach (PropertyData key in GetPropertyList(t)) {
        yield return key.GetAdjustedName(useCamelCase);
      }
    }

    public static IEnumerable<KeyValuePair<string, object>>
    GetProperties(Object o, bool useCamelCase) {
      foreach (PropertyData key in GetPropertyList(o.GetType())) {
        if (!key.HasUsableGetter()) {
          continue;
        }
        yield return new KeyValuePair<string, object>(
  key.GetAdjustedName(useCamelCase),
  key.Prop.GetValue(o, null));
      }
    }

    public static void BreakDownDateTime(
  DateTime bi,
  EInteger[] year,
  int[] lf) {
#if NET20
      DateTime dt = bi.ToUniversalTime();
#else
      DateTime dt = TimeZoneInfo.ConvertTime(bi, TimeZoneInfo.Utc);
#endif
      year[0] = EInteger.FromInt32(dt.Year);
      lf[0] = dt.Month;
      lf[1] = dt.Day;
      lf[2] = dt.Hour;
      lf[3] = dt.Minute;
      lf[4] = dt.Second;
      // lf[5] is the number of nanoseconds
      lf[5] = (int)(dt.Ticks % 10000000L) * 100;
    }

    public static DateTime BuildUpDateTime(EInteger year, int[] dt) {
      return new DateTime(
  year.ToInt32Checked(),
  dt[0],
  dt[1],
  dt[2],
  dt[3],
  dt[4],
  DateTimeKind.Utc).AddMinutes(-dt[6]).AddTicks((long)(dt[5] / 100));
    }
  }
}
