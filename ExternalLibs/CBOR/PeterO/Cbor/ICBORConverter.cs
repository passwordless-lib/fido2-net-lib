/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:ICBORConverter`1"]/*'/>
  public interface ICBORConverter<T>
  {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:ICBORConverter`1.ToCBORObject(`0)"]/*'/>
    CBORObject ToCBORObject(T obj);
  }
}
