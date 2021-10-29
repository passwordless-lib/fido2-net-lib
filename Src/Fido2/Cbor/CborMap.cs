using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

using Fido2NetLib.Objects;

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

        public void Add(string key, bool value)
        {
            items.Add(new(new CborTextString(key), new CborBoolean(value)));
        }

        public void Add(long key, CborObject value)
        {
            items.Add(new (new CborInteger(key), value));
        }

        public void Add(long key, byte[] value)
        {
            items.Add(new(new CborInteger(key), new CborByteString(value)));
        }

        public void Add(long key, long value)
        {
            items.Add(new(new CborInteger(key), new CborInteger(value)));
        }

        public void Add(string key, int value)
        {
            items.Add(new(new CborTextString(key), new CborInteger(value)));
        }

        public void Add(string key, string value)
        {
            items.Add(new(new CborTextString(key), new CborTextString(value)));
        }

        public void Add(string key, byte[] value)
        {
            items.Add(new(new CborTextString(key), new CborByteString(value)));
        }

        internal void Add(CborObject key, CborObject value)
        {
            items.Add(new (key, value));
        }

        internal void Add(string key, COSE.Algorithm value)
        {
            items.Add(new(new CborTextString(key), new CborInteger((int)value)));
        }

        internal void Add(COSE.KeyCommonParameter key, COSE.KeyType value)
        {
            items.Add(new(new CborInteger((int)key), new CborInteger((int)value)));
        }

        internal void Add(COSE.KeyCommonParameter key, COSE.Algorithm value)
        {
            items.Add(new(new CborInteger((int)key), new CborInteger((int)value)));
        }

        internal void Add(COSE.KeyTypeParameter key, COSE.EllipticCurve value)
        {
            items.Add(new(new CborInteger((int)key), new CborInteger((int)value)));
        }

        internal void Add(COSE.KeyTypeParameter key, byte[] value)
        {
            items.Add(new(new CborInteger((int)key), new CborByteString(value)));
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

        internal CborObject this[COSE.KeyCommonParameter key] => GetValue((long)key);

        internal CborObject this[COSE.EllipticCurve key] => GetValue((long)key);

        internal CborObject this[COSE.KeyType key] => GetValue((long)key);

        internal CborObject this[COSE.KeyTypeParameter key] => GetValue((long)key);

        public CborObject GetValue(long key)
        {
            foreach (var item in items)
            {
                if (item.Key is CborInteger integerKey && integerKey.Value == key)
                {
                    return item.Value;
                }
            }

            throw new KeyNotFoundException($"Key '{key}' not found");
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

                return null!;
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

        internal void Remove(string key)
        {
            for (int i = 0; i < items.Count; i++)
            {
                if (items[i].Key is CborTextString textKey && textKey.Value.Equals(key, StringComparison.Ordinal))
                {
                    items.RemoveAt(i);

                    return;
                }
            }
        }

        internal void Set(string key, CborObject value)
        {
            for (int i = 0; i < items.Count; i++)
            {
                if (items[i].Key is CborTextString textKey && textKey.Value.Equals(key, StringComparison.Ordinal))
                {
                    items[i] = new KeyValuePair<CborObject, CborObject>(new CborTextString(key), value);

                    return;
                }
            }

            items.Add(new(new CborTextString(key), value));
        }
    }
}
