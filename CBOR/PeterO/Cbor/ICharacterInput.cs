using System;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:ICharacterInput"]/*'/>
  internal interface ICharacterInput {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:ICharacterInput.ReadChar"]/*'/>
    int ReadChar();

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:ICharacterInput.Read(System.Int32[],System.Int32,System.Int32)"]/*'/>
    int Read(int[] chars, int index, int length);
  }
}
