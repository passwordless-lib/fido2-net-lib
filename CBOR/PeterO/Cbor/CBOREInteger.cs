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
  internal class CBOREInteger : ICBORNumber
  {
    public bool IsPositiveInfinity(object obj) {
      return false;
    }

    public bool IsInfinity(object obj) {
      return false;
    }

    public bool IsNegativeInfinity(object obj) {
      return false;
    }

    public bool IsNaN(object obj) {
      return false;
    }

    public double AsDouble(object obj) {
      return EFloat.FromEInteger((EInteger)obj).ToDouble();
    }

    public EDecimal AsExtendedDecimal(object obj) {
      return EDecimal.FromEInteger((EInteger)obj);
    }

    public EFloat AsExtendedFloat(object obj) {
      return EFloat.FromEInteger((EInteger)obj);
    }

    public float AsSingle(object obj) {
      return EFloat.FromEInteger((EInteger)obj).ToSingle();
    }

    public EInteger AsEInteger(object obj) {
      return (EInteger)obj;
    }

    public long AsInt64(object obj) {
      var bi = (EInteger)obj;
      if (bi.CompareTo(CBORObject.Int64MaxValue) > 0 ||
          bi.CompareTo(CBORObject.Int64MinValue) < 0) {
        throw new OverflowException("This object's value is out of range");
      }
      return (long)bi;
    }

    public bool CanFitInSingle(object obj) {
      var bigintItem = (EInteger)obj;
      EFloat ef = EFloat.FromEInteger(bigintItem);
      EFloat ef2 = EFloat.FromSingle(ef.ToSingle());
      return ef.CompareTo(ef2) == 0;
    }

    public bool CanFitInDouble(object obj) {
      var bigintItem = (EInteger)obj;
      EFloat ef = EFloat.FromEInteger(bigintItem);
      EFloat ef2 = EFloat.FromDouble(ef.ToDouble());
      return ef.CompareTo(ef2) == 0;
    }

    public bool CanFitInInt32(object obj) {
      var bi = (EInteger)obj;
      return bi.CanFitInInt32();
    }

    public bool CanFitInInt64(object obj) {
      var bi = (EInteger)obj;
      return bi.GetSignedBitLength() <= 63;
    }

    public bool CanTruncatedIntFitInInt64(object obj) {
      return this.CanFitInInt64(obj);
    }

    public bool CanTruncatedIntFitInInt32(object obj) {
      return this.CanFitInInt32(obj);
    }

    public bool IsZero(object obj) {
      return ((EInteger)obj).IsZero;
    }

    public int Sign(object obj) {
      return ((EInteger)obj).Sign;
    }

    public bool IsIntegral(object obj) {
      return true;
    }

    public int AsInt32(object obj, int minValue, int maxValue) {
      var bi = (EInteger)obj;
      if (bi.CanFitInInt32()) {
        var ret = (int)bi;
        if (ret >= minValue && ret <= maxValue) {
          return ret;
        }
      }
      throw new OverflowException("This object's value is out of range");
    }

    public object Negate(object obj) {
      var bigobj = (EInteger)obj;
      bigobj = -(EInteger)bigobj;
      return bigobj;
    }

    public object Abs(object obj) {
      return ((EInteger)obj).Abs();
    }

    public ERational AsExtendedRational(object obj) {
      return ERational.FromEInteger((EInteger)obj);
    }

    public bool IsNegative(object obj) {
      return ((EInteger)obj).Sign < 0;
    }
  }
}
