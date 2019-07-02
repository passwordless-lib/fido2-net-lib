/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using PeterO;
using PeterO.Numbers;

namespace PeterO.Cbor {
  internal class CBORInteger : ICBORNumber {
    public object Abs(object obj) {
      var val = (long)obj;
      return (val == Int32.MinValue) ? (EInteger.One << 63) : ((val < 0) ?
      -val : obj);
    }

    public EInteger AsEInteger(object obj) {
      return (EInteger)(long)obj;
    }

    public double AsDouble(object obj) {
      return (double)(long)obj;
    }

    public EDecimal AsExtendedDecimal(object obj) {
      return EDecimal.FromInt64((long)obj);
    }

    public EFloat AsExtendedFloat(object obj) {
      return EFloat.FromInt64((long)obj);
    }

    public ERational AsExtendedRational(object obj) {
      return ERational.FromInt64((long)obj);
    }

    public int AsInt32(object obj, int minValue, int maxValue) {
      var val = (long)obj;
      if (val >= minValue && val <= maxValue) {
        return (int)val;
      }
      throw new OverflowException("This object's value is out of range");
    }

    public long AsInt64(object obj) {
      return (long)obj;
    }

    public float AsSingle(object obj) {
      return (float)(long)obj;
    }

    public bool CanFitInDouble(object obj) {
      var intItem = (long)obj;
      if (intItem == Int64.MinValue) {
        return true;
      }
      intItem = (intItem < 0) ? -intItem : intItem;
      while (intItem >= (1L << 53) && (intItem & 1) == 0) {
        intItem >>= 1;
      }
      return intItem < (1L << 53);
    }

    public bool CanFitInInt32(object obj) {
      var val = (long)obj;
      return val >= Int32.MinValue && val <= Int32.MaxValue;
    }

    public bool CanFitInInt64(object obj) {
      return true;
    }

    public bool CanFitInSingle(object obj) {
      var intItem = (long)obj;
      if (intItem == Int64.MinValue) {
        return true;
      }
      intItem = (intItem < 0) ? -intItem : intItem;
      while (intItem >= (1L << 24) && (intItem & 1) == 0) {
        intItem >>= 1;
      }
      return intItem < (1L << 24);
    }

    public bool CanTruncatedIntFitInInt32(object obj) {
      var val = (long)obj;
      return val >= Int32.MinValue && val <= Int32.MaxValue;
    }

    public bool CanTruncatedIntFitInInt64(object obj) {
      return true;
    }

    public bool IsInfinity(object obj) {
      return false;
    }

    public bool IsIntegral(object obj) {
      return true;
    }

    public bool IsNaN(object obj) {
      return false;
    }

    public bool IsNegative(object obj) {
      return ((long)obj) < 0;
    }

    public bool IsNegativeInfinity(object obj) {
      return false;
    }

    public bool IsPositiveInfinity(object obj) {
      return false;
    }

    public bool IsZero(object obj) {
      return ((long)obj) == 0;
    }

    public object Negate(object obj) {
      return (((long)obj) == Int64.MinValue) ? (EInteger.One << 63) :
      (-((long)obj));
    }

    public int Sign(object obj) {
      var val = (long)obj;
      return (val == 0) ? 0 : ((val < 0) ? -1 : 1);
    }
  }
}
