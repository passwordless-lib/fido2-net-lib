/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using PeterO.Numbers;

namespace PeterO {
    /// <include file='../docs.xml'
    /// path='docs/doc[@name="T:PeterO.TrapException"]/*'/>
  [Obsolete(
  "Use ETrapException from PeterO.Numbers/com.upokecenter.numbers.")]
  public class TrapException : ArithmeticException {
    private ETrapException ete;

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="P:PeterO.TrapException.Context"]/*'/>
    public PrecisionContext Context { get {
        return new PrecisionContext(this.ete.Context);
} }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="P:PeterO.TrapException.Result"]/*'/>
    public Object Result { get {
        return this.ete.Result;
} }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="P:PeterO.TrapException.Error"]/*'/>
    public int Error { get {
        return this.ete.Error;
} }

    private TrapException() : base() {
    }

    internal static TrapException Create(ETrapException ete) {
      var ex = new TrapException();
      ex.ete = ete;
      return ex;
    }

    /// <include file='../docs.xml'
    /// path='docs/doc[@name="M:PeterO.TrapException.#ctor(System.Int32,PeterO.PrecisionContext,System.Object)"]/*'/>
    public TrapException(int flag, PrecisionContext ctx, Object result) :
      base(String.Empty) {
      Object wrappedResult = result;
      var ed = result as EDecimal;
      var er = result as ERational;
      var ef = result as EFloat;
      if (ed != null) {
 wrappedResult = new ExtendedDecimal(ed);
}
      if (er != null) {
 wrappedResult = new ExtendedRational(er);
}
      if (ef != null) {
 wrappedResult = new ExtendedFloat(ef);
}
      this.ete = new ETrapException(
  flag,
  ctx == null ? null : ctx.Ec,
  wrappedResult);
    }
  }
}
