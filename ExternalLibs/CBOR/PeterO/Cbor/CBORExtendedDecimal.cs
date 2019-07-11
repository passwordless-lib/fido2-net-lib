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
  internal class CBORExtendedDecimal : ICBORNumber
  {
    public bool IsPositiveInfinity(object obj) {
      var ed = (EDecimal)obj;
      return ed.IsPositiveInfinity();
    }

    public bool IsInfinity(object obj) {
      var ed = (EDecimal)obj;
      return ed.IsInfinity();
    }

    public bool IsNegativeInfinity(object obj) {
      var ed = (EDecimal)obj;
      return ed.IsNegativeInfinity();
    }

    public bool IsNaN(object obj) {
      var ed = (EDecimal)obj;
      return ed.IsNaN();
    }

    public double AsDouble(object obj) {
      var ed = (EDecimal)obj;
      return ed.ToDouble();
    }

    public EDecimal AsExtendedDecimal(object obj) {
      var ed = (EDecimal)obj;
      return ed;
    }

    public EFloat AsExtendedFloat(object obj) {
      var ed = (EDecimal)obj;
      return ed.ToEFloat();
    }

    public float AsSingle(object obj) {
      var ed = (EDecimal)obj;
      return ed.ToSingle();
    }

    public EInteger AsEInteger(object obj) {
      var ed = (EDecimal)obj;
      return ed.ToEInteger();
    }

    public long AsInt64(object obj) {
      var ef = (EDecimal)obj;
      if (this.CanTruncatedIntFitInInt64(obj)) {
        EInteger bi = ef.ToEInteger();
        return (long)bi;
      }
      throw new OverflowException("This object's value is out of range");
    }

    public bool CanFitInSingle(object obj) {
      var ef = (EDecimal)obj;
      return (!ef.IsFinite) ||
      (ef.CompareTo(EDecimal.FromSingle(ef.ToSingle())) == 0);
    }

    public bool CanFitInDouble(object obj) {
      var ef = (EDecimal)obj;
      return (!ef.IsFinite) ||
      (ef.CompareTo(EDecimal.FromDouble(ef.ToDouble())) == 0);
    }

    public bool CanFitInInt32(object obj) {
      return this.IsIntegral(obj) && this.CanTruncatedIntFitInInt32(obj);
    }

    public bool CanFitInInt64(object obj) {
      return this.IsIntegral(obj) && this.CanTruncatedIntFitInInt64(obj);
    }

    public bool CanTruncatedIntFitInInt64(object obj) {
      var ef = (EDecimal)obj;
      if (!ef.IsFinite) {
        return false;
      }
      if (ef.IsZero) {
        return true;
      }
      if (ef.Exponent.CompareTo((EInteger)21) >= 0) {
        return false;
      }
      EInteger bi = ef.ToEInteger();
      return bi.GetSignedBitLength() <= 63;
    }

    public bool CanTruncatedIntFitInInt32(object obj) {
      var ef = (EDecimal)obj;
      if (!ef.IsFinite) {
        return false;
      }
      if (ef.IsZero) {
        return true;
      }
      if (ef.Exponent.CompareTo((EInteger)11) >= 0) {
        return false;
      }
      EInteger bi = ef.ToEInteger();
      return bi.CanFitInInt32();
    }

    public bool IsZero(object obj) {
      var ed = (EDecimal)obj;
      return ed.IsZero;
    }

    public int Sign(object obj) {
      var ed = (EDecimal)obj;
      return ed.IsNaN() ? 2 : ed.Sign;
    }

    public bool IsIntegral(object obj) {
      var ed = (EDecimal)obj;
      return ed.IsFinite && ((ed.Exponent.Sign >= 0) ||
      (ed.CompareTo(EDecimal.FromEInteger(ed.ToEInteger())) ==
      0));
    }

    public int AsInt32(object obj, int minValue, int maxValue) {
      var ef = (EDecimal)obj;
      if (this.CanTruncatedIntFitInInt32(obj)) {
        EInteger bi = ef.ToEInteger();
        var ret = (int)bi;
        if (ret >= minValue && ret <= maxValue) {
          return ret;
        }
      }
      throw new OverflowException("This object's value is out of range");
    }

    public object Negate(object obj) {
      var ed = (EDecimal)obj;
      return ed.Negate();
    }

    public object Abs(object obj) {
      var ed = (EDecimal)obj;
      return ed.Abs();
    }

    public ERational AsExtendedRational(object obj) {
      return ERational.FromEDecimal((EDecimal)obj);
    }

    public bool IsNegative(object obj) {
      return ((EDecimal)obj).IsNegative;
    }
  }
}
