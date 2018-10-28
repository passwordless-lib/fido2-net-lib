/*
Written by Peter O. in 2013.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */

using System;

namespace PeterO {
    /// <include file='../docs.xml'
    /// path='docs/doc[@name="T:PeterO.Rounding"]/*'/>
  [Obsolete("Use ERounding from PeterO.Numbers/com.upokecenter.numbers.")]
  public enum Rounding {
    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.Up"]/*'/>
    Up,

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.Down"]/*'/>
    Down,

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.Ceiling"]/*'/>
    Ceiling,

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.Floor"]/*'/>
    Floor,

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.HalfUp"]/*'/>
    HalfUp,

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.HalfDown"]/*'/>
    HalfDown,

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.HalfEven"]/*'/>
    HalfEven,

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.Unnecessary"]/*'/>
    Unnecessary,

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.ZeroFiveUp"]/*'/>
    ZeroFiveUp,

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.Odd"]/*'/>
    Odd,

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Rounding.OddOrZeroFiveUp"]/*'/>
    OddOrZeroFiveUp
  }
}
