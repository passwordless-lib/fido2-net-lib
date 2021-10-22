using System.Collections.Generic;

namespace Fido2NetLib.Cbor
{
    internal sealed class CborArray : CborObject
    {
        public CborArray(List<CborObject> values)
        {
            Values = values;
        }

        public override CborType Type => CborType.Array;

        public int Count => Values.Count;

        public List<CborObject> Values { get; }

        public override CborObject? this[int index] => Values[index];
    }
}
