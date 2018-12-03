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
  internal class CBORDouble : ICBORNumber
  {
    public bool IsPositiveInfinity(object obj) {
      return Double.IsPositiveInfinity((double)obj);
    }

    public bool IsInfinity(object obj) {
      return Double.IsInfinity((double)obj);
    }

    public bool IsNegativeInfinity(object obj) {
      return Double.IsNegativeInfinity((double)obj);
    }

    public bool IsNaN(object obj) {
      return Double.IsNaN((double)obj);
    }

    public double AsDouble(object obj) {
      return (double)obj;
    }

    public EDecimal AsExtendedDecimal(object obj) {
      return EDecimal.FromDouble((double)obj);
    }

    public EFloat AsExtendedFloat(object obj) {
      return EFloat.FromDouble((double)obj);
    }

    public float AsSingle(object obj) {
      return (float)(double)obj;
    }

    public EInteger AsEInteger(object obj) {
      return CBORUtilities.BigIntegerFromDouble((double)obj);
    }

    public long AsInt64(object obj) {
      var fltItem = (double)obj;
      if (Double.IsNaN(fltItem)) {
        throw new OverflowException("This object's value is out of range");
      }
      fltItem = (fltItem < 0) ? Math.Ceiling(fltItem) : Math.Floor(fltItem);
      if (fltItem >= -9223372036854775808.0 && fltItem <
      9223372036854775808.0) {
        return (long)fltItem;
      }
      throw new OverflowException("This object's value is out of range");
    }

    public bool CanFitInSingle(object obj) {
      var fltItem = (double)obj;
      if (Double.IsNaN(fltItem)) {
        return true;
      }
      var sing = (float)fltItem;
      return (double)sing == (double)fltItem;
    }

    public bool CanFitInDouble(object obj) {
      return true;
    }

    public bool CanFitInInt32(object obj) {
      return this.IsIntegral(obj) && this.CanTruncatedIntFitInInt32(obj);
    }

    public bool CanFitInInt64(object obj) {
      return this.IsIntegral(obj) && this.CanTruncatedIntFitInInt64(obj);
    }

    public bool CanTruncatedIntFitInInt64(object obj) {
      var fltItem = (double)obj;
      if (Double.IsNaN(fltItem) || Double.IsInfinity(fltItem)) {
        return false;
      }
      double fltItem2 = (fltItem < 0) ? Math.Ceiling(fltItem) :
      Math.Floor(fltItem);
      return fltItem2 >= -9223372036854775808.0 && fltItem2 <
      9223372036854775808.0;
    }

    public bool CanTruncatedIntFitInInt32(object obj) {
      var fltItem = (double)obj;
      if (Double.IsNaN(fltItem) || Double.IsInfinity(fltItem)) {
        return false;
      }
      double fltItem2 = (fltItem < 0) ? Math.Ceiling(fltItem) :
      Math.Floor(fltItem);
      return fltItem2 >= Int32.MinValue && fltItem2 <= Int32.MaxValue;
    }

    public int AsInt32(object obj, int minValue, int maxValue) {
      var fltItem = (double)obj;
      if (Double.IsNaN(fltItem)) {
        throw new OverflowException("This object's value is out of range");
      }
      fltItem = (fltItem < 0) ? Math.Ceiling(fltItem) : Math.Floor(fltItem);
      if (fltItem >= minValue && fltItem <= maxValue) {
        var ret = (int)fltItem;
        return ret;
      }
      throw new OverflowException("This object's value is out of range");
    }

    public bool IsZero(object obj) {
      return (double)obj == 0.0;
    }

    public int Sign(object obj) {
      var flt = (double)obj;
      return Double.IsNaN(flt) ? 2 : ((double)flt == 0.0 ? 0 : (flt < 0.0f ?
      -1 : 1));
    }

    public bool IsIntegral(object obj) {
      var fltItem = (double)obj;
      if (Double.IsNaN(fltItem) || Double.IsInfinity(fltItem)) {
        return false;
      }
      double fltItem2 = (fltItem < 0) ? Math.Ceiling(fltItem) :
      Math.Floor(fltItem);
      return fltItem == fltItem2;
    }

    public object Negate(object obj) {
      var val = (double)obj;
      return -val;
    }

    public object Abs(object obj) {
      var val = (double)obj;
      return (val < 0) ? -val : obj;
    }

    public ERational AsExtendedRational(object obj) {
      return ERational.FromDouble((double)obj);
    }

    public bool IsNegative(object obj) {
      var dbl = (double)obj;
      long lvalue = BitConverter.ToInt64(
  BitConverter.GetBytes((double)dbl),
  0);
      return (lvalue >> 63) != 0;
    }
  }
}
