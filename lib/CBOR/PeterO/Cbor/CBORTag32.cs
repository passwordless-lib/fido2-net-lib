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
  internal class CBORTag32 : ICBORTag, ICBORConverter<Uri>
  {
    public CBORTypeFilter GetTypeFilter() {
      return CBORTypeFilter.TextString;
    }

    public CBORObject ValidateObject(CBORObject obj) {
      if (obj.Type != CBORType.TextString) {
        throw new CBORException("URI must be a text string");
      }
      if (!URIUtility.isValidIRI(obj.AsString())) {
        throw new CBORException("String is not a valid URI/IRI");
      }
      return obj;
    }

    internal static void AddConverter() {
      CBORObject.AddConverter(typeof(Uri), new CBORTag32());
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
