/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using PeterO.Numbers;

namespace PeterO.Cbor {
  internal class CBORDateConverter : ICBORToFromConverter<DateTime> {
    private static string DateTimeToString(DateTime bi) {
      var lesserFields = new int[7];
      var year = new EInteger[1];
      PropertyMap.BreakDownDateTime(bi, year, lesserFields);
      return CBORUtilities.ToAtomDateTimeString(year[0], lesserFields, true);
    }

    public CBORObject ValidateObject(CBORObject obj) {
      if (obj.Type != CBORType.TextString) {
        throw new CBORException("Not a text string");
      }
      return obj;
    }

    public DateTime FromCBORObject(CBORObject obj) {
      if (obj.HasMostOuterTag(0)) {
        return StringToDateTime(obj.AsString());
      } else if (obj.HasMostOuterTag(1)) {
        if (!obj.IsFinite) {
          throw new CBORException("Not a finite number");
        }
          EDecimal dec = obj.AsEDecimal();
          var lesserFields = new int[7];
          var year = new EInteger[1];
          CBORUtilities.BreakDownSecondsSinceEpoch(
                  dec,
                  year,
                  lesserFields);
          return PropertyMap.BuildUpDateTime(year[0], lesserFields);
      }
      throw new CBORException("Not tag 0 or 1");
    }

    public static DateTime StringToDateTime(string str) {
      var lesserFields = new int[7];
      var year = new EInteger[1];
      CBORUtilities.ParseAtomDateTimeString(str, year, lesserFields);
      return PropertyMap.BuildUpDateTime(year[0], lesserFields);
    }

    public CBORObject ToCBORObject(DateTime obj) {
      return CBORObject.FromObjectAndTag(DateTimeToString(obj), 0);
    }
  }
}
