using System.Collections;
using System.Collections.Generic;

namespace Fido2NetLib.Cbor;

public sealed class CborArray : CborObject, IEnumerable<CborObject>
{
    public CborArray()
    {
        Values = [];
    }

    public CborArray(List<CborObject> values)
    {
        Values = values;
    }

    public override CborType Type => CborType.Array;

    public int Length => Values.Count;

    public List<CborObject> Values { get; }

    public override CborObject this[int index] => Values[index];

    public void Add(CborObject value)
    {
        Values.Add(value);
    }

    public void Add(byte[] value)
    {
        Values.Add(new CborByteString(value));
    }

    public void Add(string value)
    {
        Values.Add(new CborTextString(value));
    }

    public IEnumerator<CborObject> GetEnumerator() => Values.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => Values.GetEnumerator();
}
