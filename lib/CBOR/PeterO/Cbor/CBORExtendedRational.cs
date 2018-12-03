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
  internal class CBORExtendedRational : ICBORNumber
  {
    public bool IsPositiveInfinity(object obj) {
      return ((ERational)obj).IsPositiveInfinity();
    }

    public bool IsInfinity(object obj) {
      return ((ERational)obj).IsInfinity();
    }

    public bool IsNegativeInfinity(object obj) {
      return ((ERational)obj).IsNegativeInfinity();
    }

    public bool IsNaN(object obj) {
      return ((ERational)obj).IsNaN();
    }

    public double AsDouble(object obj) {
      var er = (ERational)obj;
      return er.ToDouble();
    }

    public EDecimal AsExtendedDecimal(object obj) {
      var er = (ERational)obj;
      return

  er.ToEDecimalExactIfPossible(EContext.Decimal128.WithUnlimitedExponents());
    }

    public EFloat AsExtendedFloat(object obj) {
      var er = (ERational)obj;
      return

  er.ToEFloatExactIfPossible(EContext.Binary128.WithUnlimitedExponents());
    }

    public float AsSingle(object obj) {
      var er = (ERational)obj;
      return er.ToSingle();
    }

    public EInteger AsEInteger(object obj) {
      var er = (ERational)obj;
      return er.ToEInteger();
    }

    public long AsInt64(object obj) {
      var ef = (ERational)obj;
      if (ef.IsFinite) {
        EInteger bi = ef.ToEInteger();
        if (bi.GetSignedBitLength() <= 63) {
          return (long)bi;
        }
      }
      throw new OverflowException("This object's value is out of range");
    }

    public bool CanFitInSingle(object obj) {
      var ef = (ERational)obj;
      return (!ef.IsFinite) ||
      (ef.CompareTo(ERational.FromSingle(ef.ToSingle())) == 0);
    }

    public bool CanFitInDouble(object obj) {
      var ef = (ERational)obj;
      return (!ef.IsFinite) ||
      (ef.CompareTo(ERational.FromDouble(ef.ToDouble())) == 0);
    }

    public bool CanFitInInt32(object obj) {
      return this.IsIntegral(obj) && this.CanTruncatedIntFitInInt32(obj);
    }

    public bool CanFitInInt64(object obj) {
      return this.IsIntegral(obj) && this.CanTruncatedIntFitInInt64(obj);
    }

    public bool CanTruncatedIntFitInInt64(object obj) {
      var ef = (ERational)obj;
      if (!ef.IsFinite) {
        return false;
      }
      EInteger bi = ef.ToEInteger();
      return bi.GetSignedBitLength() <= 63;
    }

    public bool CanTruncatedIntFitInInt32(object obj) {
      var ef = (ERational)obj;
      if (!ef.IsFinite) {
        return false;
      }
      EInteger bi = ef.ToEInteger();
      return bi.CanFitInInt32();
    }

    public bool IsZero(object obj) {
      var ef = (ERational)obj;
      return ef.IsZero;
    }

    public int Sign(object obj) {
      var ef = (ERational)obj;
      return ef.Sign;
    }

    public bool IsIntegral(object obj) {
      var ef = (ERational)obj;
      if (!ef.IsFinite) {
        return false;
      }
      if (ef.Denominator.Equals(EInteger.One)) {
        return true;
      }
      // A rational number is integral if the remainder
      // of the numerator divided by the denominator is 0
      EInteger denom = ef.Denominator;
      EInteger rem = ef.Numerator % (EInteger)denom;
      return rem.IsZero;
    }

    public int AsInt32(object obj, int minValue, int maxValue) {
      var ef = (ERational)obj;
      if (ef.IsFinite) {
        EInteger bi = ef.ToEInteger();
        if (bi.CanFitInInt32()) {
          var ret = (int)bi;
          if (ret >= minValue && ret <= maxValue) {
            return ret;
          }
        }
      }
      throw new OverflowException("This object's value is out of range");
    }

    public object Negate(object obj) {
      var ed = (ERational)obj;
      return ed.Negate();
    }

    public object Abs(object obj) {
      var ed = (ERational)obj;
      return ed.Abs();
    }

    public ERational AsExtendedRational(object obj) {
      return (ERational)obj;
    }

    public bool IsNegative(object obj) {
      return ((ERational)obj).IsNegative;
    }
  }
}
