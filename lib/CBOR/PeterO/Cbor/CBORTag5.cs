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
#pragma warning disable 618
namespace PeterO.Cbor {
  internal class CBORTag5 : ICBORTag
  {
    internal static readonly CBORTypeFilter Filter = new
    CBORTypeFilter().WithArrayExactLength(
  2,
  CBORTypeFilter.UnsignedInteger.WithNegativeInteger(),
  CBORTypeFilter.UnsignedInteger.WithNegativeInteger().WithTags(2, 3));

    internal static readonly CBORTypeFilter ExtendedFilter = new
    CBORTypeFilter().WithArrayExactLength(
  2,
  CBORTypeFilter.UnsignedInteger.WithNegativeInteger().WithTags(2, 3),
  CBORTypeFilter.UnsignedInteger.WithNegativeInteger().WithTags(2, 3));

    public CBORTag5() : this(false) {
    }

    private readonly bool extended;

    public CBORTag5(bool extended) {
      this.extended = extended;
    }

    public CBORTypeFilter GetTypeFilter() {
      return this.extended ? ExtendedFilter : Filter;
    }

    internal static CBORObject ConvertToDecimalFrac(
      CBORObject o,
      bool isDecimal,
      bool extended) {
      if (o.Type != CBORType.Array) {
        throw new CBORException("Big fraction must be an array");
      }
      if (o.Count != 2) {
        throw new CBORException("Big fraction requires exactly 2 items");
      }
      if (!o[0].IsIntegral) {
        throw new CBORException("Exponent is not an integer");
      }
      if (!o[1].IsIntegral) {
        throw new CBORException("Mantissa is not an integer");
      }
      EInteger exponent = o[0].AsEInteger();
      EInteger mantissa = o[1].AsEInteger();
      if (exponent.GetSignedBitLength() > 64 && !extended) {
        throw new CBORException("Exponent is too big");
      }
      if (exponent.IsZero) {
        // Exponent is 0, so return mantissa instead
        return CBORObject.FromObject(mantissa);
      }
      // NOTE: Discards tags. See comment in CBORTag2.
      return isDecimal ?
      CBORObject.FromObject(EDecimal.Create(mantissa, exponent)) :
      CBORObject.FromObject(EFloat.Create(mantissa, exponent));
    }

    public CBORObject ValidateObject(CBORObject obj) {
      return ConvertToDecimalFrac(obj, false, this.extended);
    }
  }
}
