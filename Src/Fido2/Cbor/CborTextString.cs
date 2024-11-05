using System;

namespace Fido2NetLib.Cbor;

public sealed class CborTextString(string value) : CborObject
{
    public override CborType Type => CborType.TextString;

    public int Length => Value.Length;

    public string Value { get; } = value ?? throw new ArgumentNullException(nameof(value));

    public static implicit operator string(CborTextString value) => value.Value;

    public override bool Equals(object? obj)
    {
        return obj is CborTextString other && other.Value.Equals(Value, StringComparison.Ordinal);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Type, Value);
    }
}
