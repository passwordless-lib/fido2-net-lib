using System;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:CBOREncodeOptions"]/*'/>
  public sealed class CBOREncodeOptions {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBOREncodeOptions.None"]/*'/>
  [Obsolete("Use 'new CBOREncodeOptions(true,true)' instead. Option classes in this library will follow the form seen in JSONOptions in a later version; the approach used in this class is too complicated. 'CBOREncodeOptions.Default' contains recommended default options that may be adopted by certain CBORObject methods in the next major version.")]
    public static readonly CBOREncodeOptions None =
      new CBOREncodeOptions(0);

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBOREncodeOptions.Default"]/*'/>
    public static readonly CBOREncodeOptions Default =
      new CBOREncodeOptions(false, false);

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBOREncodeOptions.NoIndefLengthStrings"]/*'/>
  [Obsolete("Use 'new CBOREncodeOptions(false,true)' instead. Option classes in this library will follow the form seen in JSONOptions in a later version; the approach used in this class is too complicated.")]
    public static readonly CBOREncodeOptions NoIndefLengthStrings =
      new CBOREncodeOptions(1);

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBOREncodeOptions.NoDuplicateKeys"]/*'/>
  [Obsolete("Use 'new CBOREncodeOptions(true,false)' instead. Option classes in this library will follow the form seen in JSONOptions in a later version; the approach used in this class is too complicated.")]
    public static readonly CBOREncodeOptions NoDuplicateKeys =
      new CBOREncodeOptions(2);

    private readonly int value;

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBOREncodeOptions.#ctor"]/*'/>
    public CBOREncodeOptions() : this(false, false) {
}

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBOREncodeOptions.#ctor(System.Boolean,System.Boolean)"]/*'/>
    public CBOREncodeOptions(
  bool useIndefLengthStrings,
  bool allowDuplicateKeys) :
        this(useIndefLengthStrings, allowDuplicateKeys, false) {
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBOREncodeOptions.#ctor(System.Boolean,System.Boolean,System.Boolean)"]/*'/>
    public CBOREncodeOptions(
  bool useIndefLengthStrings,
  bool allowDuplicateKeys,
  bool ctap2Canonical) {
      var val = 0;
      if (!useIndefLengthStrings) {
        val |= 1;
      }
      if (!allowDuplicateKeys) {
        val |= 2;
      }
      this.value = val;
      this.Ctap2Canonical = ctap2Canonical;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBOREncodeOptions.UseIndefLengthStrings"]/*'/>
    public bool UseIndefLengthStrings {
      get {
        return (this.value & 1) == 0;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBOREncodeOptions.AllowDuplicateKeys"]/*'/>
    public bool AllowDuplicateKeys {
      get {
        return (this.value & 2) == 0;
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBOREncodeOptions.Ctap2Canonical"]/*'/>
    public bool Ctap2Canonical { get; private set; }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:CBOREncodeOptions.Value"]/*'/>
  [Obsolete("Option classes in this library will follow the form seen in JSONOptions in a later version; the approach used in this class is too complicated.")]
    public int Value {
      get {
        return this.value;
      }
    }

    private CBOREncodeOptions(int value) :
    this((value & 1) == 0, (value & 2) == 0) {
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBOREncodeOptions.Or(CBOREncodeOptions)"]/*'/>
  [Obsolete("May be removed in a later version. Option classes in this library will follow the form seen in JSONOptions in a later version; the approach used in this class is too complicated.")]
    public CBOREncodeOptions Or(CBOREncodeOptions o) {
      return new CBOREncodeOptions(this.value | o.value);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBOREncodeOptions.And(CBOREncodeOptions)"]/*'/>
  [Obsolete("May be removed in a later version. Option classes in this library will follow the form seen in JSONOptions in a later version; the approach used in this class is too complicated.")]
    public CBOREncodeOptions And(CBOREncodeOptions o) {
      return new CBOREncodeOptions(this.value & o.value);
    }
  }
}
