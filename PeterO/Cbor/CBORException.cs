/*
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:PeterO.Cbor.CBORException"]/*'/>
  public class CBORException : Exception {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.CBORException.#ctor"]/*'/>
    public CBORException() {
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.CBORException.#ctor(System.String)"]/*'/>
    public CBORException(string message) : base(message) {
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.CBORException.#ctor(System.String,System.Exception)"]/*'/>
    public CBORException(string message, Exception innerException) :
      base(message, innerException) {
    }
  }
}
