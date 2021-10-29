using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Fido2NetLib.Cbor
{
    public sealed class CborMap : CborObject, IReadOnlyDictionary<CborObject, CborObject>
    {
        private readonly List<KeyValuePair<CborObject, CborObject>> items;

        public CborMap()
        {
            items = new();
        }

        public CborMap(int capacity)
        {
            items = new(capacity);
        }

        public override CborType Type => CborType.Map;

        public int Count => items.Count;

        public IEnumerable<CborObject> Keys
        {
            get
            {
                foreach (var item in items)
                {
                    yield return item.Key;
                }
            }
        }

        public IEnumerable<CborObject> Values
        {
            get
            {
                foreach (var item in items)
                {
                    yield return item.Value;
                }
            }
        }


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

        public bool ContainsKey(CborObject key)
        {
            foreach (var (k, _) in items)
            {
                if (k.Equals(key))
                    return true;
            }

            return false;
        }

        public bool TryGetValue(CborObject key, [MaybeNullWhen(false)] out CborObject value)
        {
            value = this[key];

            return value != null;
        }

        public IEnumerator<KeyValuePair<CborObject, CborObject>> GetEnumerator()
        {
            return items.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return items.GetEnumerator();
        }

        public CborObject? this[CborObject key]
        {
            get
            {
                foreach (var item in items)
                {
                    if (item.Key.Equals(key))
                    {
                        return item.Value;
                    }
                }

                return null;
            }
        }

        public override CborObject? this[string name]
        {
            get
            {
                foreach (var item in items)
                {
                    if (item.Key is CborTextString keyText && keyText.Value.Equals(name, StringComparison.Ordinal))
                    {
                        return item.Value;
                    }
                }
                return null;
            }
        }

    }
}
