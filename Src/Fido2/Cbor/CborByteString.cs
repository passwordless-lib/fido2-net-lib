using System;

namespace Fido2NetLib.Cbor;

public sealed class CborByteString(byte[] value) : CborObject
{
    public override CborType Type => CborType.ByteString;

    public byte[] Value { get; } = value ?? throw new ArgumentNullException(nameof(value));

    public int Length => Value.Length;

    public static implicit operator byte[](CborByteString value) => value.Value;
}
