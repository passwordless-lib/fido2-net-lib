/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
#pragma warning disable 618
namespace PeterO.Cbor {
  internal class CBORTag4 : ICBORTag
  {
    public CBORTag4() : this(false) {
    }

    private readonly bool extended;

    public CBORTag4(bool extended) {
      this.extended = extended;
    }

    public CBORTypeFilter GetTypeFilter() {
      return this.extended ? CBORTag5.ExtendedFilter : CBORTag5.Filter;
    }

    public CBORObject ValidateObject(CBORObject obj) {
      return CBORTag5.ConvertToDecimalFrac(obj, true, this.extended);
    }
  }
}
