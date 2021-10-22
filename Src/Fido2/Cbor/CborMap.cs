using System;
using System.Collections.Generic;

namespace Fido2NetLib.Cbor
{
    public sealed class CborMap : CborObject
    {
        private readonly List<CborProperty> properties = new ();

        public CborMap()
        {
        }

        public override CborType Type => CborType.Map;

        public int Count => properties.Count;

        public void Add(string name, CborObject value)
        {
            properties.Add(new CborProperty(name, value));
        }

        public override CborObject? this[string name]
        {
            get
            {
                foreach (var property in properties)
                {
                    if (property.Name.Equals(name, StringComparison.Ordinal))
                    {
                        return property.Value;
                    }
                }
                return null;
            }
        }

    }
}
