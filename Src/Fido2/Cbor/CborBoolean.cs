using System;

namespace Fido2NetLib.Cbor
{
    internal sealed class CborBoolean : CborObject
    {
        public CborBoolean(bool value)
        {
            Value = value;
        }

        public override CborType Type => CborType.Boolean;

        public bool Value { get; }

        public override int GetHashCode()
        {
            return HashCode.Combine(Type, Value);
        }
    }
}
