using System;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:PeterO.Cbor.ICBORObjectConverter`1"]/*'/>
  public interface ICBORToFromConverter<T> : ICBORConverter<T> {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.ICBORObjectConverter`1.FromCBORObject(PeterO.Cbor.CBORObject)"]/*'/>
    T FromCBORObject(CBORObject cbor);
  }
}
