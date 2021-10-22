namespace Fido2NetLib.Cbor
{
    internal sealed class CborInteger : CborObject
    {
        public CborInteger(long value)
        {
            Value = value;
        }

        public override CborType Type => CborType.Integer;

        public long Value { get; }
    }
}
