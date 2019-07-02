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
  internal class CBORTag27 : ICBORTag
  {
    public CBORTypeFilter GetTypeFilter() {
      return new CBORTypeFilter().WithArrayMinLength(1, CBORTypeFilter.Any);
    }

    public CBORObject ValidateObject(CBORObject obj) {
      if (obj.Type != CBORType.Array || obj.Count < 1) {
        throw new CBORException("Not an array, or is an empty array.");
      }
      return obj;
    }
  }
}
