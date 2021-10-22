namespace Fido2NetLib.Cbor
{
    internal readonly struct CborProperty
    {
        public CborProperty(string name, CborObject value)
        {
            Name = name;
            Value = value;
        }

        public string Name { get; }

        public CborObject Value { get; }
    }
}
