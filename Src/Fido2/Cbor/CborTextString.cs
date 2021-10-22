namespace Fido2NetLib.Cbor
{
    internal sealed class CborTextString : CborObject
    {
        public CborTextString(string value)
        {
            Value = value;
        }

        public override CborType Type => CborType.TextString;

        public int Length => Value.Length;

        public string Value { get; }
    }
}
