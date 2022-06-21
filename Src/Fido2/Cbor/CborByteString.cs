namespace Fido2NetLib.Cbor
{
    public sealed class CborByteString : CborObject
    {
        public CborByteString(byte[] value)
        {
            Value = value;
        }

        public override CborType Type => CborType.ByteString;

        public byte[] Value { get; }

        public int Length => Value.Length;
    }
}
