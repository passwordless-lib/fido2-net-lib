using System;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:ICBORObjectConverter`1"]/*'/>
  public interface ICBORToFromConverter<T> : ICBORConverter<T> {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:ICBORObjectConverter`1.FromCBORObject(CBORObject)"]/*'/>
    T FromCBORObject(CBORObject cbor);
  }
}
