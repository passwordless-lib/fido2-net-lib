using System;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:PeterO.Cbor.PODOptions"]/*'/>
    public class PODOptions {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.PODOptions.#ctor"]/*'/>
    public PODOptions() : this(true, true) {
}

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.PODOptions.#ctor(System.Boolean,System.Boolean)"]/*'/>
    public PODOptions(bool removeIsPrefix, bool useCamelCase) {
        #pragma warning disable 618
      this.RemoveIsPrefix = removeIsPrefix;
        #pragma warning restore 618
      this.UseCamelCase = useCamelCase;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:PeterO.Cbor.PODOptions.Default"]/*'/>
    public static readonly PODOptions Default = new PODOptions();

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:PeterO.Cbor.PODOptions.RemoveIsPrefix"]/*'/>
  [Obsolete("Property name conversion may change, making this property obsolete.")]
        public bool RemoveIsPrefix { get; private set; }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:PeterO.Cbor.PODOptions.UseCamelCase"]/*'/>
    public bool UseCamelCase { get; private set; }
    }
}
