/*
Written by Peter O. in 2013.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:CBORType"]/*'/>
  public enum CBORType {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORType.Number"]/*'/>
    Number,

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORType.Boolean"]/*'/>
    Boolean,

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORType.SimpleValue"]/*'/>
    SimpleValue,

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORType.ByteString"]/*'/>
    ByteString,

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORType.TextString"]/*'/>
    TextString,

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORType.Array"]/*'/>
    Array,

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORType.Map"]/*'/>
    Map
  }
}
