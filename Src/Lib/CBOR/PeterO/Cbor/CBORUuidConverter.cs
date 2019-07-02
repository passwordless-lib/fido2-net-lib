/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;

namespace PeterO.Cbor {
  internal class CBORUuidConverter : ICBORToFromConverter<Guid>
  {
    private CBORObject ValidateObject(CBORObject obj) {
      if (obj.Type != CBORType.ByteString) {
        throw new CBORException("UUID must be a byte string");
      }
      byte[] bytes = obj.GetByteString();
      if (bytes.Length != 16) {
        throw new CBORException("UUID must be 16 bytes long");
      }
      return obj;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTag37.ToCBORObject(System.Guid)"]/*'/>
    public CBORObject ToCBORObject(Guid obj) {
      byte[] bytes = PropertyMap.UUIDToBytes(obj);
      return CBORObject.FromObjectAndTag(bytes, (int)37);
    }

    public Guid FromCBORObject(CBORObject obj) {
      if (!obj.HasMostOuterTag(37)) {
        throw new CBORException("Must have outermost tag 37");
      }
      this.ValidateObject(obj);
      byte[] bytes = obj.GetByteString();
      var guidChars = new char[36];
      string hex = "0123456789abcdef";
      var index = 0;
      for (var i = 0; i < 16; ++i) {
       if (i == 4 || i == 6 || i == 8 || i == 10) {
         guidChars[index++] = '-';
       }
       guidChars[index++] = hex[(int)(bytes[i] >> 4) & 15];
       guidChars[index++] = hex[(int)bytes[i] & 15];
      }
      string guidString = new String(guidChars);
      return new Guid(guidString);
    }
  }
}
