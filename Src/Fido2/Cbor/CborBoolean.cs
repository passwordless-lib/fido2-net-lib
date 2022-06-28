using System;

namespace Fido2NetLib.Cbor
{
    public sealed class CborBoolean : CborObject
    {
        public static readonly CborBoolean True  = new(true);
        public static readonly CborBoolean False = new(false);

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

        public static explicit operator CborBoolean(bool value) => value ? True : False;

        public static implicit operator bool(CborBoolean value) => value.Value;
    }
}
