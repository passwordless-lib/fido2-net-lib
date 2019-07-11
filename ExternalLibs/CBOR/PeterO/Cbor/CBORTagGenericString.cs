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
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:CBORTagGenericString"]/*'/>
  internal class CBORTagGenericString : ICBORTag
  {
    public CBORTypeFilter GetTypeFilter() {
      return CBORTypeFilter.TextString;
    }

    public CBORObject ValidateObject(CBORObject obj) {
      if (obj.Type == CBORType.TextString) {
        throw new CBORException("Not a text string");
      }
      return obj;
    }
  }
}
