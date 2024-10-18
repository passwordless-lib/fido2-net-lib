using System;

namespace Fido2NetLib.Cbor;

internal sealed class CborInteger(long value) : CborObject
{
    public override CborType Type => CborType.Integer;

    public long Value { get; } = value;

    public override bool Equals(object? obj)
    {
        return obj is CborInteger other && other.Value == Value;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Type, Value);
    }
}
