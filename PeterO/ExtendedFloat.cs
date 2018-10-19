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
    /// path='docs/doc[@name="T:PeterO.ExtendedFloat"]/*'/>
[Obsolete(
  "Use EFloat from PeterO.Numbers/com.upokecenter.numbers and the output of this class's ToString method.")]
  public sealed class ExtendedFloat : IComparable<ExtendedFloat>,
 IEquatable<ExtendedFloat> {
    private readonly EFloat ef;

    internal ExtendedFloat(EFloat ef) {
      this.ef = ef;
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="P:PeterO.ExtendedFloat.Exponent"]/*'/>
    public BigInteger Exponent {
      get {
        return new BigInteger(this.Ef.Exponent);
      }
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="P:PeterO.ExtendedFloat.UnsignedMantissa"]/*'/>
    public BigInteger UnsignedMantissa {
      get {
        return new BigInteger(this.Ef.UnsignedMantissa);
      }
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="P:PeterO.ExtendedFloat.Mantissa"]/*'/>
    public BigInteger Mantissa {
      get {
        return new BigInteger(this.Ef.Mantissa);
      }
    }

    internal static ExtendedFloat ToLegacy(EFloat ei) {
      return new ExtendedFloat(ei);
    }

    internal static EFloat FromLegacy(ExtendedFloat bei) {
      return bei.Ef;
    }

    #region Equals and GetHashCode implementation
    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.EqualsInternal(PeterO.ExtendedFloat)"]/*'/>
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public bool EqualsInternal(ExtendedFloat otherValue) {
      if (otherValue == null) {
        throw new ArgumentNullException(nameof(otherValue));
      }
      return this.Ef.EqualsInternal(otherValue.Ef);
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.Equals(PeterO.ExtendedFloat)"]/*'/>
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public bool Equals(ExtendedFloat other) {
      if (other == null) {
        throw new ArgumentNullException(nameof(other));
      }
      return this.Ef.Equals(other.Ef);
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.Equals(System.Object)"]/*'/>
    public override bool Equals(object obj) {
      var bi = obj as ExtendedFloat;
      return (bi == null) ? false : this.Ef.Equals(bi.Ef);
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.GetHashCode"]/*'/>
    public override int GetHashCode() {
      return this.Ef.GetHashCode();
    }
    #endregion

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.Create(System.Int32,System.Int32)"]/*'/>
    public static ExtendedFloat Create(int mantissaSmall, int exponentSmall) {
      return new ExtendedFloat(EFloat.Create(mantissaSmall, exponentSmall));
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.Create(PeterO.BigInteger,PeterO.BigInteger)"]/*'/>
    public static ExtendedFloat Create(
  BigInteger mantissa,
  BigInteger exponent) {
      if (mantissa == null) {
        throw new ArgumentNullException(nameof(mantissa));
      }
      if (exponent == null) {
        throw new ArgumentNullException(nameof(exponent));
      }
      return new ExtendedFloat(EFloat.Create(mantissa.Ei, exponent.Ei));
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.FromString(System.String,System.Int32,System.Int32,PeterO.PrecisionContext)"]/*'/>
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public static ExtendedFloat FromString(
  string str,
  int offset,
  int length,
  PrecisionContext ctx) {
      try {
        return new ExtendedFloat(
  EFloat.FromString(
  str,
  offset,
  length,
  ctx == null ? null : ctx.Ec));
      } catch (ETrapException ex) {
        throw TrapException.Create(ex);
      }
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.FromString(System.String)"]/*'/>
    public static ExtendedFloat FromString(string str) {
      return new ExtendedFloat(EFloat.FromString(str));
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.ToString"]/*'/>
    public override string ToString() {
      return this.Ef.ToString();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.ExtendedFloat.One"]/*'/>
#if CODE_ANALYSIS
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
      "Microsoft.Security",
      "CA2104",
      Justification = "ExtendedFloat is immutable")]
#endif
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public static readonly ExtendedFloat One =
     new ExtendedFloat(EFloat.One);

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.ExtendedFloat.Zero"]/*'/>
#if CODE_ANALYSIS
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
      "Microsoft.Security",
      "CA2104",
      Justification = "ExtendedFloat is immutable")]
#endif
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public static readonly ExtendedFloat Zero =
     new ExtendedFloat(EFloat.Zero);

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.ExtendedFloat.NegativeZero"]/*'/>
#if CODE_ANALYSIS
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
      "Microsoft.Security",
      "CA2104",
      Justification = "ExtendedFloat is immutable")]
#endif
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public static readonly ExtendedFloat NegativeZero =
     new ExtendedFloat(EFloat.NegativeZero);

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.ExtendedFloat.Ten"]/*'/>
#if CODE_ANALYSIS
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
      "Microsoft.Security",
      "CA2104",
      Justification = "ExtendedFloat is immutable")]
#endif

    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public static readonly ExtendedFloat Ten =
     new ExtendedFloat(EFloat.Ten);

    //----------------------------------------------------------------

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.ExtendedFloat.NaN"]/*'/>
    public static readonly ExtendedFloat NaN =
     new ExtendedFloat(EFloat.NaN);

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.ExtendedFloat.SignalingNaN"]/*'/>
    public static readonly ExtendedFloat SignalingNaN =
     new ExtendedFloat(EFloat.SignalingNaN);

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.ExtendedFloat.PositiveInfinity"]/*'/>
    public static readonly ExtendedFloat PositiveInfinity =
     new ExtendedFloat(EFloat.PositiveInfinity);

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="F:PeterO.ExtendedFloat.NegativeInfinity"]/*'/>
    public static readonly ExtendedFloat NegativeInfinity =
     new ExtendedFloat(EFloat.NegativeInfinity);

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.IsNegativeInfinity"]/*'/>
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public bool IsNegativeInfinity() {
      return this.Ef.IsNegativeInfinity();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.IsPositiveInfinity"]/*'/>
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public bool IsPositiveInfinity() {
      return this.Ef.IsPositiveInfinity();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.IsNaN"]/*'/>
    public bool IsNaN() {
      return this.Ef.IsNaN();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.IsInfinity"]/*'/>
    public bool IsInfinity() {
      return this.Ef.IsInfinity();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="P:PeterO.ExtendedFloat.IsNegative"]/*'/>
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public bool IsNegative {
      get {
        return this.Ef.IsNegative;
      }
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.IsQuietNaN"]/*'/>
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public bool IsQuietNaN() {
      return this.Ef.IsQuietNaN();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.IsSignalingNaN"]/*'/>
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public bool IsSignalingNaN() {
      return this.Ef.IsSignalingNaN();
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.ExtendedFloat.CompareTo(PeterO.ExtendedFloat)"]/*'/>
    public int CompareTo(ExtendedFloat other) {
      return this.Ef.CompareTo(other == null ? null : other.Ef);
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="P:PeterO.ExtendedFloat.Sign"]/*'/>
    [Obsolete("Use EFloat from PeterO.Numbers/com.upokecenter.numbers.")]
    public int Sign {
      get {
        return this.Ef.Sign;
      }
    }

    internal EFloat Ef {
      get {
        return this.ef;
      }
    }
  }
}
