using System;
using System.Collections.Generic;

namespace Fido2NetLib.Cbor
{
    public sealed class CborMap : CborObject
    {
        private readonly List<(CborObject, CborObject)> items = new ();

        public CborMap()
        {
        }

        public override CborType Type => CborType.Map;

        public int Count => items.Count;

        public void Add(string key, CborObject value)
        {
            items.Add(new (new CborTextString(key), value));
        }

        public void Add(long key, CborObject value)
        {
            items.Add(new (new CborInteger(key), value));
        }

        internal void Add(CborObject key, CborObject value)
        {
            items.Add(new (key, value));
        }

        public CborObject? this[CborObject key]
        {
            get
            {
                foreach (var (k, v) in items)
                {
                    if (k.Equals(key))
                    {
                        return v;
                    }
                }

                return null;
            }
        }

        public override CborObject? this[string name]
        {
            get
            {
                foreach (var (k, v) in items)
                {
                    if (k is CborTextString keyText && keyText.Value.Equals(name, StringComparison.Ordinal))
                    {
                        return v;
                    }
                }
                return null;
            }
        }

    }
}
