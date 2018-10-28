/*
Written by Peter O. in 2013.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using System.Text;
using PeterO;
using PeterO.Numbers;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:CBORUtilities"]/*'/>
  internal static class CBORUtilities {
    private const string HexAlphabet = "0123456789ABCDEF";

    public static void ToBase16(StringBuilder str, byte[] data) {
      if (data == null) {
        throw new ArgumentNullException(nameof(data));
      }
      int length = data.Length;
      for (var i = 0; i < length; ++i) {
        str.Append(HexAlphabet[(data[i] >> 4) & 15]);
        str.Append(HexAlphabet[data[i] & 15]);
      }
    }

    public static bool ByteArrayEquals(byte[] a, byte[] b) {
      if (a == null) {
        return b == null;
      }
      if (b == null) {
        return false;
      }
      if (a.Length != b.Length) {
        return false;
      }
      for (var i = 0; i < a.Length; ++i) {
        if (a[i] != b[i]) {
          return false;
        }
      }
      return true;
    }

    public static int ByteArrayHashCode(byte[] a) {
      if (a == null) {
        return 0;
      }
      var ret = 19;
      unchecked {
        ret = (ret * 31) + a.Length;
        for (var i = 0; i < a.Length; ++i) {
          ret = (ret * 31) + a[i];
        }
      }
      return ret;
    }

    public static int ByteArrayCompare(byte[] a, byte[] b) {
      if (a == null) {
        return (b == null) ? 0 : -1;
      }
      if (b == null) {
        return 1;
      }
      int c = Math.Min(a.Length, b.Length);
      for (var i = 0; i < c; ++i) {
        if (a[i] != b[i]) {
          return (a[i] < b[i]) ? -1 : 1;
        }
      }
      return (a.Length != b.Length) ? ((a.Length < b.Length) ? -1 : 1) : 0;
    }

    public static string DoubleToString(double dbl) {
      return EFloat.FromDouble(dbl).ToShortestString(EContext.Binary64);
    }

    public static string SingleToString(float sing) {
      return EFloat.FromSingle(sing).ToShortestString(EContext.Binary32);
    }

    public static EInteger BigIntegerFromSingle(float flt) {
      int value = BitConverter.ToInt32(BitConverter.GetBytes((float)flt), 0);
      var fpexponent = (int)((value >> 23) & 0xff);
      if (fpexponent == 255) {
        throw new OverflowException("Value is infinity or NaN");
      }
      int mantissa = value & 0x7fffff;
      if (fpexponent == 0) {
        ++fpexponent;
      } else {
        mantissa |= 1 << 23;
      }
      if (mantissa == 0) {
        return EInteger.Zero;
      }
      fpexponent -= 150;
      while ((mantissa & 1) == 0) {
        ++fpexponent;
        mantissa >>= 1;
      }
      bool neg = (value >> 31) != 0;
      if (fpexponent == 0) {
        if (neg) {
          mantissa = -mantissa;
        }
        return (EInteger)mantissa;
      }
      if (fpexponent > 0) {
        // Value is an integer
        var bigmantissa = (EInteger)mantissa;
        bigmantissa <<= fpexponent;
        if (neg) {
          bigmantissa = -(EInteger)bigmantissa;
        }
        return bigmantissa;
      } else {
        // Value has a fractional part
        int exp = -fpexponent;
        for (var i = 0; i < exp && mantissa != 0; ++i) {
          mantissa >>= 1;
        }
        return (EInteger)mantissa;
      }
    }

    public static string LongToString(long longValue) {
      if (longValue == Int64.MinValue) {
        return "-9223372036854775808";
      }
      if (longValue == 0L) {
        return "0";
      }
      if (longValue == (long)Int32.MinValue) {
        return "-2147483648";
      }
      bool neg = longValue < 0;
      var count = 0;
      char[] chars;
      int intlongValue = unchecked((int)longValue);
      if ((long)intlongValue == longValue) {
        chars = new char[12];
        count = 11;
        if (neg) {
          intlongValue = -intlongValue;
        }
        while (intlongValue > 43698) {
          int intdivValue = intlongValue / 10;
        char digit = HexAlphabet[(int)(intlongValue - (intdivValue * 10))];
        chars[count--] = digit;
        intlongValue = intdivValue;
      }
      while (intlongValue > 9) {
        int intdivValue = (intlongValue * 26215) >> 18;
        char digit = HexAlphabet[(int)(intlongValue - (intdivValue * 10))];
        chars[count--] = digit;
        intlongValue = intdivValue;
      }
      if (intlongValue != 0) {
        chars[count--] = HexAlphabet[(int)intlongValue];
      }
      if (neg) {
        chars[count] = '-';
      } else {
        ++count;
      }
      return new String(chars, count, 12 - count);
      } else {
        chars = new char[24];
        count = 23;
        if (neg) {
          longValue = -longValue;
        }
        while (longValue > 43698) {
          long divValue = longValue / 10;
        char digit = HexAlphabet[(int)(longValue - (divValue * 10))];
        chars[count--] = digit;
        longValue = divValue;
      }
      while (longValue > 9) {
        long divValue = (longValue * 26215) >> 18;
        char digit = HexAlphabet[(int)(longValue - (divValue * 10))];
        chars[count--] = digit;
        longValue = divValue;
      }
      if (longValue != 0) {
        chars[count--] = HexAlphabet[(int)longValue];
      }
      if (neg) {
        chars[count] = '-';
      } else {
        ++count;
      }
      return new String(chars, count, 24 - count);
      }
    }

    private static EInteger FloorDiv(EInteger a, EInteger n) {
      return a.Sign >= 0 ? a.Divide(n) : EInteger.FromInt32(-1).Subtract(
                EInteger.FromInt32(-1).Subtract(a).Divide(n));
    }

    private static EInteger FloorMod(EInteger a, EInteger n) {
      return a.Subtract(FloorDiv(a, n).Multiply(n));
    }

    private static readonly int[] ValueNormalDays = { 0, 31, 28, 31, 30, 31, 30,
      31, 31, 30,
      31, 30, 31 };

    private static readonly int[] ValueLeapDays = { 0, 31, 29, 31, 30, 31, 30,
      31, 31, 30,
      31, 30, 31 };

    private static readonly int[] ValueNormalToMonth = { 0, 0x1f, 0x3b, 90, 120,
      0x97, 0xb5,
      0xd4, 0xf3, 0x111, 0x130, 0x14e, 0x16d };

    private static readonly int[] ValueLeapToMonth = { 0, 0x1f, 60, 0x5b, 0x79,
      0x98, 0xb6,
      0xd5, 0xf4, 0x112, 0x131, 0x14f, 0x16e };

    public static void GetNormalizedPartProlepticGregorian(
          EInteger year,
          int month,
          EInteger day,
          EInteger[] dest) {
      // NOTE: This method assumes month is 1 to 12
      if (month <= 0 || month > 12) {
        throw new ArgumentOutOfRangeException(nameof(month));
      }
      EInteger num4 = EInteger.FromInt32(4);
      EInteger num100 = EInteger.FromInt32(100);
      EInteger num101 = EInteger.FromInt32(101);
      EInteger num146097 = EInteger.FromInt32(146097);
      EInteger num400 = EInteger.FromInt32(400);
      int[] dayArray = (year.Remainder(num4).Sign != 0 || (
                    year.Remainder(num100).Sign == 0 &&
                    year.Remainder(num400).Sign != 0)) ?
         ValueNormalDays : ValueLeapDays;
      if (day.CompareTo(num101) > 0) {
        EInteger count = day.Subtract(num100).Divide(num146097);
        day = day.Subtract(count.Multiply(num146097));
        year = year.Add(count.Multiply(num400));
      }
      while (true) {
        EInteger days = EInteger.FromInt32(dayArray[month]);
        if (day.Sign > 0 && day.CompareTo(days) <= 0) {
          break;
        }
        if (day.CompareTo(days) > 0) {
          day = day.Subtract(days);
          if (month == 12) {
            month = 1;
            year = year.Add(EInteger.One);
            dayArray = (year.Remainder(num4).Sign != 0 || (
                    year.Remainder(num100).Sign == 0 &&
                    year.Remainder(num400).Sign != 0)) ? ValueNormalDays :
              ValueLeapDays;
          } else {
            ++month;
          }
        }
        if (day.Sign <= 0) {
          int divResult = (month - 2) / 12;
          year = year.Add(EInteger.FromInt32(divResult));
          month = ((month - 2) - (12 * divResult)) + 1;
          dayArray = (year.Remainder(num4).Sign != 0 || (
                    year.Remainder(num100).Sign == 0 &&
             year.Remainder(num400).Sign != 0)) ? ValueNormalDays :
                    ValueLeapDays;
          day = day.Add(EInteger.FromInt32(dayArray[month]));
        }
      }
      dest[0] = year;
      dest[1] = EInteger.FromInt32(month);
      dest[2] = day;
    }

    public static EInteger GetNumberOfDaysProlepticGregorian(
         EInteger year,
         int month,
         int mday) {
      // NOTE: month = 1 is January, year = 1 is year 1
      if (month <= 0 || month > 12) {
 throw new ArgumentException();
}
      if (mday <= 0 || mday > 31) {
 throw new ArgumentException();
}
      EInteger num4 = EInteger.FromInt32(4);
      EInteger num100 = EInteger.FromInt32(100);
      EInteger num400 = EInteger.FromInt32(400);
      EInteger numDays = EInteger.Zero;
      var startYear = 1970;
      if (year.CompareTo(EInteger.FromInt32(startYear)) < 0) {
        for (EInteger ei = EInteger.FromInt32(startYear - 1);
             ei.CompareTo(year) > 0;
             ei = ei.Subtract(EInteger.One)) {
          numDays = numDays.Subtract(EInteger.FromInt32(365));
          if (!(ei.Remainder(num4).Sign != 0 || (
                    ei.Remainder(num100).Sign == 0 &&
                    ei.Remainder(num400).Sign != 0))) {
            numDays = numDays.Subtract(EInteger.One);
          }
        }
        if (year.Remainder(num4).Sign != 0 || (
                    year.Remainder(num100).Sign == 0 &&
                    year.Remainder(num400).Sign != 0)) {
          numDays = numDays.Subtract(
             EInteger.FromInt32(365 - ValueNormalToMonth[month]));
          numDays = numDays.Subtract(
             EInteger.FromInt32(ValueNormalDays[month] - mday + 1));
        } else {
          numDays = numDays.Subtract(
             EInteger.FromInt32(366 - ValueLeapToMonth[month]));
          numDays = numDays.Subtract(
             EInteger.FromInt32(ValueLeapDays[month] - mday + 1));
        }
      } else {
        bool isNormalYear = year.Remainder(num4).Sign != 0 ||
        (year.Remainder(num100).Sign == 0 && year.Remainder(num400).Sign !=
            0);
        EInteger ei = EInteger.FromInt32(startYear);
        EInteger num401 = EInteger.FromInt32(401);
        EInteger num146097 = EInteger.FromInt32(146097);
        for (; ei.Add(num401).CompareTo(year) < 0;
            ei = ei.Add(num400)) {
          numDays = numDays.Add(num146097);
        }
        for (; ei.CompareTo(year) < 0;
            ei = ei.Add(EInteger.One)) {
          numDays = numDays.Add(EInteger.FromInt32(365));
          if (!(ei.Remainder(num4).Sign != 0 || (
                    ei.Remainder(num100).Sign == 0 &&
                    ei.Remainder(num400).Sign != 0))) {
            numDays = numDays.Add(EInteger.One);
          }
        }
        int yearToMonth = isNormalYear ? ValueNormalToMonth[month - 1] :
          ValueLeapToMonth[month - 1];
        numDays = numDays.Add(EInteger.FromInt32(yearToMonth))
             .Add(EInteger.FromInt32(mday - 1));
      }
      return numDays;
    }

    public static void BreakDownSecondsSinceEpoch(
      EDecimal edec,
      EInteger[] year,
      int[] lesserFields) {
      EInteger integerPart = edec.ToEInteger();
      EDecimal fractionalPart = edec.Abs()
        .Subtract(EDecimal.FromEInteger(integerPart).Abs());
      int nanoseconds = fractionalPart .Multiply(EDecimal.FromInt32(1000000000))
       .ToInt32Checked();
      var normPart = new EInteger[3];
      EInteger days = FloorDiv(
  integerPart,
  EInteger.FromInt32(86400)).Add(EInteger.One);
      int secondsInDay = FloorMod(
  integerPart,
  EInteger.FromInt32(86400)).ToInt32Checked();
      GetNormalizedPartProlepticGregorian(
     EInteger.FromInt32(1970),
     1,
     days,
     normPart);
      lesserFields[0] = normPart[1].ToInt32Checked();
      lesserFields[1] = normPart[2].ToInt32Checked();
      lesserFields[2] = secondsInDay / 3600;
      lesserFields[3] = (secondsInDay % 3600) / 60;
      lesserFields[4] = secondsInDay % 60;
      lesserFields[5] = nanoseconds / 100;
      lesserFields[6] = 0;
      year[0] = normPart[0];
    }

    public static bool NameStartsWithWord(String name, String word) {
      int wl = word.Length;
      return name.Length > wl && name.Substring(0, wl).Equals(word) &&
              !(name[wl] >= 'a' && name[wl] <= 'z') &&
              !(name[wl] >= '0' && name[wl] <= '9');
    }

    public static String FirstCharLower(String name) {
      if (name.Length > 0 && name[0] >= 'A' && name[0] <= 'Z') {
              var sb = new StringBuilder();
              sb.Append((char)(name[0] + 0x20));
              sb.Append(name.Substring(1));
              return sb.ToString();
      }
      return name;
    }

    public static String FirstCharUpper(String name) {
      if (name.Length > 0 && name[0] >= 'a' && name[0] <= 'z') {
              var sb = new StringBuilder();
              sb.Append((char)(name[0] - 0x20));
              sb.Append(name.Substring(1));
              return sb.ToString();
      }
      return name;
    }

    private static bool IsValidDateTime(int[] dateTime) {
      if (dateTime == null || dateTime.Length < 8) {
        return false;
      }
      if (dateTime[1] < 1 || dateTime[1] > 12 || dateTime[2] < 1) {
        return false;
      }
      bool leap = IsLeapYear(dateTime[0]);
      if (dateTime[1] == 4 || dateTime[1] == 6 || dateTime[1] == 9 ||
        dateTime[1] == 11) {
        if (dateTime[2] > 30) {
          return false;
        }
      } else if (dateTime[1] == 2) {
        if (dateTime[2] > (leap ? 29 : 28)) {
          return false;
        }
      } else {
        if (dateTime[2] > 31) {
          return false;
        }
      }
      return !(dateTime[3] < 0 || dateTime[4] < 0 || dateTime[5] < 0 ||
dateTime[3] >= 24 || dateTime[4] >= 60 || dateTime[5] >= 61 ||
dateTime[6] < 0 ||
dateTime[6] >= 1000000000 || dateTime[7] <= -1440 ||
        dateTime[7] >= 1440);
    }

    private static bool IsLeapYear(int yr) {
      yr %= 400;
      if (yr < 0) {
        yr += 400;
      }
      return (((yr % 4) == 0) && ((yr % 100) != 0)) || ((yr % 400) == 0);
    }

    public static void ParseAtomDateTimeString(
  string str,
  EInteger[] bigYearArray,
  int[] lf) {
  int[] d = ParseAtomDateTimeString(str);
   bigYearArray[0] = EInteger.FromInt32(d[0]);
   Array.Copy(d, 1, lf, 0, 7);
    }

    private static int[] ParseAtomDateTimeString(string str) {
      var bad = false;
      if (str.Length < 19) {
        throw new ArgumentException("Invalid date/time");
      }
      for (var i = 0; i < 19 && !bad; ++i) {
        if (i == 4 || i == 7) {
          bad |= str[i] != '-';
        } else if (i == 13 || i == 16) {
          bad |= str[i] != ':';
        } else if (i == 10) {
          bad |= str[i] != 'T';
          /*lowercase t not used to separate date/time,
    following RFC 4287 sec. 3.3*/ } else {
          bad |= str[i] < '0' || str[i] >
'9';
        }
      }
      if (bad) {
        throw new ArgumentException("Invalid date/time");
      }
      int year = ((str[0] - '0') * 1000) + ((str[1] - '0') * 100) +
        (str[2] - '0') * 10 + (str[3] - '0');
      int month = ((str[5] - '0') * 10) + (str[6] - '0');
      int day = ((str[8] - '0') * 10) + (str[9] - '0');
      int hour = ((str[11] - '0') * 10) + (str[12] - '0');
      int minute = ((str[14] - '0') * 10) + (str[15] - '0');
      int second = ((str[17] - '0') * 10) + (str[18] - '0');
      var index = 19;
      var nanoSeconds = 0;
      if (index <= str.Length && str[index] == '.') {
        var icount = 0;
        ++index;
        while (index < str.Length) {
          if (str[index] < '0' || str[index] > '9') {
            break;
          }
          if (icount < 9) {
            nanoSeconds = nanoSeconds * 10 + (str[index] - '0');
            ++icount;
          }
          ++index;
        }
        while (icount < 9) {
          nanoSeconds *= 10;
          ++icount;
        }
      }
      var utcToLocal = 0;
      if (index + 1 == str.Length && str[index] == 'Z') {
        /*lowercase z not used to indicate UTC,
          following RFC 4287 sec. 3.3*/
        utcToLocal = 0;
      } else if (index + 6 == str.Length) {
        bad = false;
        for (var i = 0; i < 6 && !bad; ++i) {
          if (i == 0) {
            bad |= str[index + i] != '-' && str[index + i] != '+';
          } else if (i == 3) {
            bad |= str[index + i] != ':';
          } else {
            bad |= str[index + i] < '0' || str[index + i] > '9';
          }
        }
        if (bad) {
          throw new ArgumentException("Invalid date/time");
        }
        bool neg = str[index] == '-';
        int tzhour = ((str[index + 1] - '0') * 10) + (str[index + 2] - '0');
        int tzminute = ((str[index + 4] - '0') * 10) + (str[index + 5] - '0');
        if (tzminute >= 60) {
          throw new ArgumentException("Invalid date/time");
        }
        utcToLocal = (neg ? -1 : 1) * (tzhour * 60) + tzminute;
      } else {
        throw new ArgumentException("Invalid date/time");
      }
      int[] dt = new[] { year, month, day, hour, minute, second,
        nanoSeconds, utcToLocal};
      if (!IsValidDateTime(dt)) {
        throw new ArgumentException("Invalid date/time");
      }
      return dt;
    }

    public static string ToAtomDateTimeString(
      EInteger bigYear,
      int[] lesserFields,
      bool fracIsNanoseconds) {
      // TODO: fracIsNanoseconds is a parameter
      // for compatibility purposes only
      if (lesserFields[6] != 0) {
        throw new NotSupportedException(
          "Local time offsets not supported");
      }
      int smallYear = bigYear.ToInt32Checked();
      if (smallYear < 0) {
  throw new ArgumentException("year (" + smallYear +
    ") is not greater or equal to 0");
}
if (smallYear > 9999) {
  throw new ArgumentException("year (" + smallYear +
    ") is not less or equal to 9999");
}
      int month = lesserFields[0];
      int day = lesserFields[1];
      int hour = lesserFields[2];
      int minute = lesserFields[3];
      int second = lesserFields[4];
      int fracSeconds = lesserFields[5];
      var charbuf = new char[32];
      charbuf[0] = (char)('0' + ((smallYear / 1000) % 10));
      charbuf[1] = (char)('0' + ((smallYear / 100) % 10));
      charbuf[2] = (char)('0' + ((smallYear / 10) % 10));
      charbuf[3] = (char)('0' + (smallYear % 10));
      charbuf[4] = '-';
      charbuf[5] = (char)('0' + ((month / 10) % 10));
      charbuf[6] = (char)('0' + (month % 10));
      charbuf[7] = '-';
      charbuf[8] = (char)('0' + ((day / 10) % 10));
      charbuf[9] = (char)('0' + (day % 10));
      charbuf[10] = 'T';
      charbuf[11] = (char)('0' + ((hour / 10) % 10));
      charbuf[12] = (char)('0' + (hour % 10));
      charbuf[13] = ':';
      charbuf[14] = (char)('0' + ((minute / 10) % 10));
      charbuf[15] = (char)('0' + (minute % 10));
      charbuf[16] = ':';
      charbuf[17] = (char)('0' + ((second / 10) % 10));
      charbuf[18] = (char)('0' + (second % 10));
      var charbufLength = 19;
      if (!fracIsNanoseconds) {
         int milliseconds = fracSeconds / 1000000;
         if (milliseconds > 0) {
          charbuf[19] = '.';
          charbuf[20] = (char)('0' + ((milliseconds / 100) % 10));
          charbuf[21] = (char)('0' + ((milliseconds / 10) % 10));
          charbuf[22] = (char)('0' + (milliseconds % 10));
          charbuf[23] = 'Z';
          charbufLength += 5;
        } else {
          charbuf[19] = 'Z';
          ++charbufLength;
        }
      } else {
        if (fracSeconds > 0) {
          charbuf[19] = '.';
 ++charbufLength;
int digitdiv = 100000000;
int index = 20;
while (digitdiv > 0 && fracSeconds != 0) {
 int digit = (fracSeconds / digitdiv) % 10;
 fracSeconds -= digit * digitdiv;
 charbuf[index++] = (char)('0' + digit);
 ++charbufLength;
 digitdiv /= 10;
}
          charbuf[index] = 'Z';
          ++charbufLength;
        } else {
          charbuf[19] = 'Z';
          ++charbufLength;
        }
      }
      return new String(charbuf, 0, charbufLength);
    }

    public static EInteger BigIntegerFromDouble(double dbl) {
      long lvalue = BitConverter.ToInt64(
  BitConverter.GetBytes((double)dbl),
  0);
      int value0 = unchecked((int)(lvalue & 0xffffffffL));
      int value1 = unchecked((int)((lvalue >> 32) & 0xffffffffL));
      var floatExponent = (int)((value1 >> 20) & 0x7ff);
      bool neg = (value1 >> 31) != 0;
      if (floatExponent == 2047) {
        throw new OverflowException("Value is infinity or NaN");
      }
      value1 &= 0xfffff;  // Mask out the exponent and sign
      if (floatExponent == 0) {
        ++floatExponent;
      } else {
        value1 |= 0x100000;
      }
      if ((value1 | value0) != 0) {
        while ((value0 & 1) == 0) {
          value0 >>= 1;
          value0 &= 0x7fffffff;
          value0 = unchecked(value0 | (value1 << 31));
          value1 >>= 1;
          ++floatExponent;
        }
      }
      floatExponent -= 1075;
      var bytes = new byte[9];
      EInteger bigmantissa;
      bytes[0] = (byte)(value0 & 0xff);
      bytes[1] = (byte)((value0 >> 8) & 0xff);
      bytes[2] = (byte)((value0 >> 16) & 0xff);
      bytes[3] = (byte)((value0 >> 24) & 0xff);
      bytes[4] = (byte)(value1 & 0xff);
      bytes[5] = (byte)((value1 >> 8) & 0xff);
      bytes[6] = (byte)((value1 >> 16) & 0xff);
      bytes[7] = (byte)((value1 >> 24) & 0xff);
      bytes[8] = (byte)0;
      bigmantissa = EInteger.FromBytes(bytes, true);
      if (floatExponent == 0) {
        if (neg) {
          bigmantissa = -bigmantissa;
        }
        return bigmantissa;
      }
      if (floatExponent > 0) {
        // Value is an integer
        bigmantissa <<= floatExponent;
        if (neg) {
          bigmantissa = -(EInteger)bigmantissa;
        }
        return bigmantissa;
      } else {
        // Value has a fractional part
        int exp = -floatExponent;
        bigmantissa >>= exp;
        if (neg) {
          bigmantissa = -(EInteger)bigmantissa;
        }
        return bigmantissa;
      }
    }

    public static float HalfPrecisionToSingle(int value) {
      int negvalue = (value >= 0x8000) ? (1 << 31) : 0;
      value &= 0x7fff;
      if (value >= 0x7c00) {
        value = (int)(0x3fc00 | (value & 0x3ff)) << 13 | negvalue;
        return BitConverter.ToSingle(
  BitConverter.GetBytes(value),
  0);
      }
      if (value > 0x400) {
        value = (int)((value + 0x1c000) << 13) | negvalue;
        return BitConverter.ToSingle(
  BitConverter.GetBytes(value),
  0);
      }
      if ((value & 0x400) == value) {
        value = (int)((value == 0) ? 0 : 0x38800000) | negvalue;
        return BitConverter.ToSingle(
  BitConverter.GetBytes(value),
  0);
      } else {
        // denormalized
        int m = value & 0x3ff;
        value = 0x1c400;
        while ((m >> 10) == 0) {
          value -= 0x400;
          m <<= 1;
        }
        value = ((value | (m & 0x3ff)) << 13) | negvalue;
        return BitConverter.ToSingle(BitConverter.GetBytes((int)value), 0);
      }
    }
  }
}
