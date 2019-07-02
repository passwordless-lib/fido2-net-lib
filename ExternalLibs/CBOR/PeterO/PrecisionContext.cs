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
    /// path='docs/doc[@name="T:PeterO.PrecisionContext"]/*'/>
  [Obsolete("Use EContext from PeterO.Numbers/com.upokecenter.numbers.")]
  public class PrecisionContext {
    private readonly EContext ec;

    internal EContext Ec {
      get {
        return this.ec;
      }
    }

    internal PrecisionContext(EContext ec) {
      this.ec = ec;
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.PrecisionContext.#ctor(System.Int32,PeterO.Rounding,System.Int32,System.Int32,System.Boolean)"]/*'/>
    public PrecisionContext(
 int precision,
 Rounding rounding,
 int exponentMinSmall,
 int exponentMaxSmall,
 bool clampNormalExponents) {
      throw new NotSupportedException("This class is now obsolete.");
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.PrecisionContext.ToString"]/*'/>
    public override string ToString() {
      return String.Empty;
    }
  }
}
