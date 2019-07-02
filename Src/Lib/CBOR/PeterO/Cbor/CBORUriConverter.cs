/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;

namespace PeterO.Cbor {
  internal class CBORUriConverter : ICBORToFromConverter<Uri>
  {
    private CBORObject ValidateObject(CBORObject obj) {
      if (obj.Type != CBORType.TextString) {
        throw new CBORException("URI must be a text string");
      }
      if (!URIUtility.isValidIRI(obj.AsString())) {
        throw new CBORException("String is not a valid URI/IRI");
      }
      return obj;
    }

    public Uri FromCBORObject(CBORObject obj) {
      if (obj.HasMostOuterTag(32)) {
        this.ValidateObject(obj);
        try {
         return new Uri(obj.AsString());
        } catch (Exception ex) {
         throw new CBORException(ex.Message, ex);
        }
      }
      throw new CBORException();
    }

    public CBORObject ToCBORObject(Uri uri) {
      if (uri == null) {
        throw new ArgumentNullException(nameof(uri));
      }
      string uriString = uri.ToString();
      return CBORObject.FromObjectAndTag(uriString, (int)32);
    }
  }
}
