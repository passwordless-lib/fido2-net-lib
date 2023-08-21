using System;

namespace Fido2NetLib.Cbor;

public sealed class CborByteString : CborObject
{
    public CborByteString(byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);

        Value = value;
    }

    public override CborType Type => CborType.ByteString;

    public byte[] Value { get; }

    public int Length => Value.Length;

    public static implicit operator byte[](CborByteString value) => value.Value;
}
