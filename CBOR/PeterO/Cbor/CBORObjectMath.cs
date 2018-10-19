/*
Written by Peter O. in 2013.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using PeterO;
using PeterO.Numbers;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:PeterO.Cbor.CBORObjectMath"]/*'/>
  internal static class CBORObjectMath {
    public static CBORObject Addition(CBORObject a, CBORObject b) {
      if (a == null) {
        throw new ArgumentNullException(nameof(a));
      }
      if (b == null) {
        throw new ArgumentNullException(nameof(b));
      }
      if (a.Type != CBORType.Number) {
        throw new ArgumentException("a.Type (" + a.Type +
          ") is not equal to " + CBORType.Number);
      }
      if (b.Type != CBORType.Number) {
        throw new ArgumentException("b.Type (" + b.Type +
          ") is not equal to " + CBORType.Number);
      }
      object objA = a.ThisItem;
      object objB = b.ThisItem;
      int typeA = a.ItemType;
      int typeB = b.ItemType;
      if (typeA == CBORObject.CBORObjectTypeInteger && typeB ==
      CBORObject.CBORObjectTypeInteger) {
        var valueA = (long)objA;
        var valueB = (long)objB;
        if ((valueA < 0 && valueB < Int64.MinValue - valueA) ||
                (valueA > 0 && valueB > Int64.MaxValue - valueA)) {
          // would overflow, convert to EInteger
          return CBORObject.FromObject(((EInteger)valueA) +
          (EInteger)valueB);
        }
        return CBORObject.FromObject(valueA + valueB);
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedRational ||
             typeB == CBORObject.CBORObjectTypeExtendedRational) {
        ERational e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedRational(objA);
        ERational e2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedRational(objB);
        return CBORObject.FromObject(e1.Add(e2));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedDecimal ||
             typeB == CBORObject.CBORObjectTypeExtendedDecimal) {
        EDecimal e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedDecimal(objA);
        EDecimal e2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedDecimal(objB);
        return CBORObject.FromObject(e1.Add(e2));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedFloat || typeB ==
      CBORObject.CBORObjectTypeExtendedFloat ||
               typeA == CBORObject.CBORObjectTypeDouble || typeB ==
               CBORObject.CBORObjectTypeDouble ||
               typeA == CBORObject.CBORObjectTypeSingle || typeB ==
               CBORObject.CBORObjectTypeSingle) {
        EFloat e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedFloat(objA);
        EFloat e2 = CBORObject.GetNumberInterface(typeB).AsExtendedFloat(objB);
        return CBORObject.FromObject(e1.Add(e2));
      } else {
        EInteger b1 = CBORObject.GetNumberInterface(typeA).AsEInteger(objA);
        EInteger b2 = CBORObject.GetNumberInterface(typeB).AsEInteger(objB);
        return CBORObject.FromObject(b1 + (EInteger)b2);
      }
    }

    public static CBORObject Subtract(CBORObject a, CBORObject b) {
      if (a == null) {
        throw new ArgumentNullException(nameof(a));
      }
      if (b == null) {
        throw new ArgumentNullException(nameof(b));
      }
      if (a.Type != CBORType.Number) {
        throw new ArgumentException("a.Type (" + a.Type +
          ") is not equal to " + CBORType.Number);
      }
      if (b.Type != CBORType.Number) {
        throw new ArgumentException("b.Type (" + b.Type +
          ") is not equal to " + CBORType.Number);
      }
      object objA = a.ThisItem;
      object objB = b.ThisItem;
      int typeA = a.ItemType;
      int typeB = b.ItemType;
      if (typeA == CBORObject.CBORObjectTypeInteger && typeB ==
      CBORObject.CBORObjectTypeInteger) {
        var valueA = (long)objA;
        var valueB = (long)objB;
        if ((valueB < 0 && Int64.MaxValue + valueB < valueA) ||
                (valueB > 0 && Int64.MinValue + valueB > valueA)) {
          // would overflow, convert to EInteger
          return CBORObject.FromObject(((EInteger)valueA) -
          (EInteger)valueB);
        }
        return CBORObject.FromObject(valueA - valueB);
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedRational ||
             typeB == CBORObject.CBORObjectTypeExtendedRational) {
        ERational e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedRational(objA);
        ERational e2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedRational(objB);
        return CBORObject.FromObject(e1.Subtract(e2));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedDecimal ||
             typeB == CBORObject.CBORObjectTypeExtendedDecimal) {
        EDecimal e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedDecimal(objA);
        EDecimal e2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedDecimal(objB);
        return CBORObject.FromObject(e1.Subtract(e2));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedFloat || typeB ==
      CBORObject.CBORObjectTypeExtendedFloat ||
               typeA == CBORObject.CBORObjectTypeDouble || typeB ==
               CBORObject.CBORObjectTypeDouble ||
               typeA == CBORObject.CBORObjectTypeSingle || typeB ==
               CBORObject.CBORObjectTypeSingle) {
        EFloat e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedFloat(objA);
        EFloat e2 = CBORObject.GetNumberInterface(typeB).AsExtendedFloat(objB);
        return CBORObject.FromObject(e1.Subtract(e2));
      } else {
        EInteger b1 = CBORObject.GetNumberInterface(typeA).AsEInteger(objA);
        EInteger b2 = CBORObject.GetNumberInterface(typeB).AsEInteger(objB);
        return CBORObject.FromObject(b1 - (EInteger)b2);
      }
    }

    public static CBORObject Multiply(CBORObject a, CBORObject b) {
      if (a == null) {
        throw new ArgumentNullException(nameof(a));
      }
      if (b == null) {
        throw new ArgumentNullException(nameof(b));
      }
      if (a.Type != CBORType.Number) {
        throw new ArgumentException("a.Type (" + a.Type +
          ") is not equal to " + CBORType.Number);
      }
      if (b.Type != CBORType.Number) {
        throw new ArgumentException("b.Type (" + b.Type +
          ") is not equal to " + CBORType.Number);
      }
      object objA = a.ThisItem;
      object objB = b.ThisItem;
      int typeA = a.ItemType;
      int typeB = b.ItemType;
      if (typeA == CBORObject.CBORObjectTypeInteger && typeB ==
      CBORObject.CBORObjectTypeInteger) {
        var valueA = (long)objA;
        var valueB = (long)objB;
        bool apos = valueA > 0L;
        bool bpos = valueB > 0L;
        if (
          (apos && ((!bpos && (Int64.MinValue / valueA) > valueB) ||
          (bpos && valueA > (Int64.MaxValue / valueB)))) ||
          (!apos && ((!bpos && valueA != 0L &&
          (Int64.MaxValue / valueA) > valueB) ||
          (bpos && valueA < (Int64.MinValue / valueB))))) {
          // would overflow, convert to EInteger
          var bvalueA = (EInteger)valueA;
          var bvalueB = (EInteger)valueB;
          return CBORObject.FromObject(bvalueA * (EInteger)bvalueB);
        }
        return CBORObject.FromObject(valueA * valueB);
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedRational ||
             typeB == CBORObject.CBORObjectTypeExtendedRational) {
        ERational e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedRational(objA);
        ERational e2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedRational(objB);
        return CBORObject.FromObject(e1.Multiply(e2));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedDecimal ||
             typeB == CBORObject.CBORObjectTypeExtendedDecimal) {
        EDecimal e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedDecimal(objA);
        EDecimal e2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedDecimal(objB);
        return CBORObject.FromObject(e1.Multiply(e2));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedFloat || typeB ==
      CBORObject.CBORObjectTypeExtendedFloat ||
               typeA == CBORObject.CBORObjectTypeDouble || typeB ==
               CBORObject.CBORObjectTypeDouble ||
               typeA == CBORObject.CBORObjectTypeSingle || typeB ==
               CBORObject.CBORObjectTypeSingle) {
        EFloat e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedFloat(objA);
        EFloat e2 = CBORObject.GetNumberInterface(typeB).AsExtendedFloat(objB);
        return CBORObject.FromObject(e1.Multiply(e2));
      } else {
        EInteger b1 = CBORObject.GetNumberInterface(typeA).AsEInteger(objA);
        EInteger b2 = CBORObject.GetNumberInterface(typeB).AsEInteger(objB);
        return CBORObject.FromObject(b1 * (EInteger)b2);
      }
    }

    public static CBORObject Divide(CBORObject a, CBORObject b) {
      if (a == null) {
        throw new ArgumentNullException(nameof(a));
      }
      if (b == null) {
        throw new ArgumentNullException(nameof(b));
      }
      if (a.Type != CBORType.Number) {
        throw new ArgumentException("a.Type (" + a.Type +
          ") is not equal to " + CBORType.Number);
      }
      if (b.Type != CBORType.Number) {
        throw new ArgumentException("b.Type (" + b.Type +
          ") is not equal to " + CBORType.Number);
      }
      object objA = a.ThisItem;
      object objB = b.ThisItem;
      int typeA = a.ItemType;
      int typeB = b.ItemType;
      if (typeA == CBORObject.CBORObjectTypeInteger && typeB ==
      CBORObject.CBORObjectTypeInteger) {
        var valueA = (long)objA;
        var valueB = (long)objB;
        if (valueB == 0) {
          return (valueA == 0) ? CBORObject.NaN : ((valueA < 0) ?
            CBORObject.NegativeInfinity : CBORObject.PositiveInfinity);
        }
        if (valueA == Int64.MinValue && valueB == -1) {
          return CBORObject.FromObject(valueA).Negate();
        }
        long quo = valueA / valueB;
        long rem = valueA - (quo * valueB);
        return (rem == 0) ? CBORObject.FromObject(quo) :
        CBORObject.FromObject(
  ERational.Create(
  (EInteger)valueA,
  (EInteger)valueB));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedRational ||
             typeB == CBORObject.CBORObjectTypeExtendedRational) {
        ERational e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedRational(objA);
        ERational e2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedRational(objB);
        return CBORObject.FromObject(e1.Divide(e2));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedDecimal ||
             typeB == CBORObject.CBORObjectTypeExtendedDecimal) {
        EDecimal e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedDecimal(objA);
        EDecimal e2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedDecimal(objB);
        if (e1.IsZero && e2.IsZero) {
          return CBORObject.NaN;
        }
        EDecimal eret = e1.Divide(e2, null);
        // If either operand is infinity or NaN, the result
        // is already exact. Likewise if the result is a finite number.
        if (!e1.IsFinite || !e2.IsFinite || eret.IsFinite) {
          return CBORObject.FromObject(eret);
        }
        ERational er1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedRational(objA);
        ERational er2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedRational(objB);
        return CBORObject.FromObject(er1.Divide(er2));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedFloat || typeB ==
      CBORObject.CBORObjectTypeExtendedFloat ||
               typeA == CBORObject.CBORObjectTypeDouble || typeB ==
               CBORObject.CBORObjectTypeDouble ||
               typeA == CBORObject.CBORObjectTypeSingle || typeB ==
               CBORObject.CBORObjectTypeSingle) {
        EFloat e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedFloat(objA);
        EFloat e2 = CBORObject.GetNumberInterface(typeB).AsExtendedFloat(objB);
        if (e1.IsZero && e2.IsZero) {
          return CBORObject.NaN;
        }
        EFloat eret = e1.Divide(e2, null);
        // If either operand is infinity or NaN, the result
        // is already exact. Likewise if the result is a finite number.
        if (!e1.IsFinite || !e2.IsFinite || eret.IsFinite) {
          return CBORObject.FromObject(eret);
        }
        ERational er1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedRational(objA);
        ERational er2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedRational(objB);
        return CBORObject.FromObject(er1.Divide(er2));
      } else {
        EInteger b1 = CBORObject.GetNumberInterface(typeA).AsEInteger(objA);
        EInteger b2 = CBORObject.GetNumberInterface(typeB).AsEInteger(objB);
        if (b2.IsZero) {
          return b1.IsZero ? CBORObject.NaN : ((b1.Sign < 0) ?
            CBORObject.NegativeInfinity : CBORObject.PositiveInfinity);
        }
        EInteger bigrem;
        EInteger bigquo;
{
EInteger[] divrem = b1.DivRem(b2);
bigquo = divrem[0];
bigrem = divrem[1]; }
        return bigrem.IsZero ? CBORObject.FromObject(bigquo) :
        CBORObject.FromObject(ERational.Create(b1, b2));
      }
    }

    public static CBORObject Remainder(CBORObject a, CBORObject b) {
      if (a == null) {
        throw new ArgumentNullException(nameof(a));
      }
      if (b == null) {
        throw new ArgumentNullException(nameof(b));
      }
      if (a.Type != CBORType.Number) {
        throw new ArgumentException("a.Type (" + a.Type +
          ") is not equal to " + CBORType.Number);
      }
      if (b.Type != CBORType.Number) {
        throw new ArgumentException("b.Type (" + b.Type +
          ") is not equal to " + CBORType.Number);
      }
      object objA = a.ThisItem;
      object objB = b.ThisItem;
      int typeA = a.ItemType;
      int typeB = b.ItemType;
      if (typeA == CBORObject.CBORObjectTypeInteger && typeB ==
      CBORObject.CBORObjectTypeInteger) {
        var valueA = (long)objA;
        var valueB = (long)objB;
        return (valueA == Int64.MinValue && valueB == -1) ?
        CBORObject.FromObject(0) : CBORObject.FromObject(valueA % valueB);
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedRational ||
             typeB == CBORObject.CBORObjectTypeExtendedRational) {
        ERational e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedRational(objA);
        ERational e2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedRational(objB);
        return CBORObject.FromObject(e1.Remainder(e2));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedDecimal ||
             typeB == CBORObject.CBORObjectTypeExtendedDecimal) {
        EDecimal e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedDecimal(objA);
        EDecimal e2 =
        CBORObject.GetNumberInterface(typeB).AsExtendedDecimal(objB);
        return CBORObject.FromObject(e1.Remainder(e2, null));
      }
      if (typeA == CBORObject.CBORObjectTypeExtendedFloat || typeB ==
      CBORObject.CBORObjectTypeExtendedFloat ||
               typeA == CBORObject.CBORObjectTypeDouble || typeB ==
               CBORObject.CBORObjectTypeDouble ||
               typeA == CBORObject.CBORObjectTypeSingle || typeB ==
               CBORObject.CBORObjectTypeSingle) {
        EFloat e1 =
        CBORObject.GetNumberInterface(typeA).AsExtendedFloat(objA);
        EFloat e2 = CBORObject.GetNumberInterface(typeB).AsExtendedFloat(objB);
        return CBORObject.FromObject(e1.Remainder(e2, null));
      } else {
        EInteger b1 = CBORObject.GetNumberInterface(typeA).AsEInteger(objA);
        EInteger b2 = CBORObject.GetNumberInterface(typeB).AsEInteger(objB);
        return CBORObject.FromObject(b1 % (EInteger)b2);
      }
    }
  }
}
