#pragma warning disable CS3021 // Type or member does not need a CLSCompliant attribute because the assembly does not have a CLSCompliant attribute
/*
Written by Peter O. in 2013.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using PeterO.Numbers;

namespace PeterO {
    /// <include file='../docs.xml'
    /// path='docs/doc[@name="T:PeterO.BigInteger"]/*'/>
  public sealed partial class BigInteger {
    /// <include file='../docs.xml'
    /// path='docs/doc[@name="P:PeterO.BigInteger.Zero"]/*'/>
    [CLSCompliant(false)] [Obsolete(
  "Use EInteger from PeterO.Numbers/com.upokecenter.numbers and the output of this class's ToString method.")]
        public static BigInteger Zero
        {
            get {
        return ValueZeroValue;
      }
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="P:PeterO.BigInteger.One"]/*'/>
    [CLSCompliant(false)] [Obsolete(
  "Use EInteger from PeterO.Numbers/com.upokecenter.numbers and the output of this class's ToString method.")]
        public static BigInteger One {
      get {
        return ValueOneValue;
      }
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.BigInteger.Equals(PeterO.BigInteger)"]/*'/>
        [Obsolete(
  "Use EInteger from PeterO.Numbers/com.upokecenter.numbers and the output of this class's ToString method.")]
        public bool Equals(BigInteger other) {
      return this.Equals((object)other);
    }
  }
}
