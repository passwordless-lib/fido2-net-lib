using System;

namespace Fido2NetLib.Cbor;

internal sealed class CborInteger : CborObject
{
    public CborInteger(long value)
    {
        Value = value;
    }

    public override CborType Type => CborType.Integer;

    public long Value { get; }

    public override bool Equals(object? obj)
    {
        return obj is CborInteger other && other.Value == Value;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Type, Value);
    }
}
