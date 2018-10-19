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
    /// path='docs/doc[@name="T:PeterO.Cbor.CBORDataUtilities"]/*'/>
  public static class CBORDataUtilities {
    private const int MaxSafeInt = 214748363;

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.CBORDataUtilities.ParseJSONNumber(System.String)"]/*'/>
    public static CBORObject ParseJSONNumber(string str) {
      return ParseJSONNumber(str, false, false);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.CBORDataUtilities.ParseJSONNumber(System.String,System.Boolean,System.Boolean)"]/*'/>
    public static CBORObject ParseJSONNumber(
      string str,
      bool integersOnly,
      bool positiveOnly) {
      return ParseJSONNumber(str, integersOnly, positiveOnly, false);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.CBORDataUtilities.ParseJSONNumber(System.String,System.Boolean,System.Boolean,System.Boolean)"]/*'/>
    public static CBORObject ParseJSONNumber(
      string str,
      bool integersOnly,
      bool positiveOnly,
      bool preserveNegativeZero) {
      if (String.IsNullOrEmpty(str)) {
        return null;
      }
      var offset = 0;
      var negative = false;
      if (str[0] == '-' && !positiveOnly) {
        negative = true;
        ++offset;
      }
      var mantInt = 0;
      FastInteger2 mant = null;
      var mantBuffer = 0;
      var mantBufferMult = 1;
      var expBuffer = 0;
      var expBufferMult = 1;
      var haveDecimalPoint = false;
      var haveDigits = false;
      var haveDigitsAfterDecimal = false;
      var haveExponent = false;
      var newScaleInt = 0;
      FastInteger2 newScale = null;
      int i = offset;
      // Ordinary number
      if (i < str.Length && str[i] == '0') {
        ++i;
        haveDigits = true;
        if (i == str.Length) {
          if (preserveNegativeZero && negative) {
            return CBORObject.FromObject(
             EDecimal.NegativeZero);
          }
          return CBORObject.FromObject(0);
        }
        if (!integersOnly) {
          if (str[i] == '.') {
            haveDecimalPoint = true;
            ++i;
          } else if (str[i] == 'E' || str[i] == 'e') {
            haveExponent = true;
          } else {
            return null;
          }
        } else {
          return null;
        }
      }
      for (; i < str.Length; ++i) {
        if (str[i] >= '0' && str[i] <= '9') {
          var thisdigit = (int)(str[i] - '0');
          if (mantInt > MaxSafeInt) {
            if (mant == null) {
              mant = new FastInteger2(mantInt);
              mantBuffer = thisdigit;
              mantBufferMult = 10;
            } else {
              if (mantBufferMult >= 1000000000) {
                mant.Multiply(mantBufferMult).AddInt(mantBuffer);
                mantBuffer = thisdigit;
                mantBufferMult = 10;
              } else {
                mantBufferMult *= 10;
                mantBuffer = (mantBuffer << 3) + (mantBuffer << 1);
                mantBuffer += thisdigit;
              }
            }
          } else {
            mantInt *= 10;
            mantInt += thisdigit;
          }
          haveDigits = true;
          if (haveDecimalPoint) {
            haveDigitsAfterDecimal = true;
            if (newScaleInt == Int32.MinValue) {
newScale = newScale ?? (new FastInteger2(newScaleInt));
              newScale.AddInt(-1);
            } else {
              --newScaleInt;
            }
          }
        } else if (!integersOnly && str[i] == '.') {
          if (!haveDigits) {
            // no digits before the decimal point
            return null;
          }
          if (haveDecimalPoint) {
            return null;
          }
          haveDecimalPoint = true;
        } else if (!integersOnly && (str[i] == 'E' || str[i] == 'e')) {
          haveExponent = true;
          ++i;
          break;
        } else {
          return null;
        }
      }
      if (!haveDigits || (haveDecimalPoint && !haveDigitsAfterDecimal)) {
        return null;
      }
      if (mant != null && (mantBufferMult != 1 || mantBuffer != 0)) {
        mant.Multiply(mantBufferMult).AddInt(mantBuffer);
      }
      if (haveExponent) {
        FastInteger2 exp = null;
        var expInt = 0;
        offset = 1;
        haveDigits = false;
        if (i == str.Length) {
          return null;
        }
        if (str[i] == '+' || str[i] == '-') {
          if (str[i] == '-') {
            offset = -1;
          }
          ++i;
        }
        for (; i < str.Length; ++i) {
          if (str[i] >= '0' && str[i] <= '9') {
            haveDigits = true;
            var thisdigit = (int)(str[i] - '0');
            if (expInt > MaxSafeInt) {
              if (exp == null) {
                exp = new FastInteger2(expInt);
                expBuffer = thisdigit;
                expBufferMult = 10;
              } else {
                if (expBufferMult >= 1000000000) {
                  exp.Multiply(expBufferMult).AddInt(expBuffer);
                  expBuffer = thisdigit;
                  expBufferMult = 10;
                } else {
                  // multiply expBufferMult and expBuffer each by 10
                  expBufferMult = (expBufferMult << 3) + (expBufferMult << 1);
                  expBuffer = (expBuffer << 3) + (expBuffer << 1);
                  expBuffer += thisdigit;
                }
              }
            } else {
              expInt *= 10;
              expInt += thisdigit;
            }
          } else {
            return null;
          }
        }
        if (!haveDigits) {
          return null;
        }
        if (exp != null && (expBufferMult != 1 || expBuffer != 0)) {
          exp.Multiply(expBufferMult).AddInt(expBuffer);
        }
      if (offset >= 0 && newScaleInt == 0 && newScale == null && exp == null) {
          newScaleInt = expInt;
        } else if (exp == null) {
newScale = newScale ?? (new FastInteger2(newScaleInt));
          if (offset < 0) {
            newScale.SubtractInt(expInt);
          } else if (expInt != 0) {
            newScale.AddInt(expInt);
          }
        } else {
newScale = newScale ?? (new FastInteger2(newScaleInt));
          if (offset < 0) {
            newScale.Subtract(exp);
          } else {
            newScale.Add(exp);
          }
        }
      }
      if (i != str.Length) {
        // End of the string wasn't reached, so isn't a number
        return null;
      }
      if ((newScale == null && newScaleInt == 0) || (newScale != null &&
                    newScale.Sign == 0)) {
        // No fractional part
        if (mant != null && mant.CanFitInInt32()) {
          mantInt = mant.AsInt32();
          mant = null;
        }
        if (mant == null) {
          // NOTE: mantInt can only be 0 or greater, so overflow is impossible
#if DEBUG
          if (mantInt < 0) {
            throw new ArgumentException("mantInt (" + mantInt +
              ") is less than 0");
          }
#endif

          if (negative) {
            mantInt = -mantInt;
            if (preserveNegativeZero && mantInt == 0) {
              return CBORObject.FromObject(
                EDecimal.NegativeZero);
            }
          }
          return CBORObject.FromObject(mantInt);
        } else {
          EInteger bigmant2 = mant.AsBigInteger();
          if (negative) {
            bigmant2 = -(EInteger)bigmant2;
          }
          return CBORObject.FromObject(bigmant2);
        }
      } else {
        EInteger bigmant = (mant == null) ? ((EInteger)mantInt) :
          mant.AsBigInteger();
        EInteger bigexp = (newScale == null) ? ((EInteger)newScaleInt) :
          newScale.AsBigInteger();
        if (negative) {
          bigmant = -(EInteger)bigmant;
        }
        EDecimal edec;
        edec = EDecimal.Create(
          bigmant,
          bigexp);
        if (negative && preserveNegativeZero && bigmant.IsZero) {
          EDecimal negzero = EDecimal.NegativeZero;
          negzero = negzero.Quantize(bigexp, null);
          edec = negzero.Subtract(edec);
        }
        return CBORObject.FromObject(edec);
      }
    }
  }
}
