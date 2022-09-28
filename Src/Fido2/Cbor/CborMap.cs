using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Cbor;

public sealed class CborMap : CborObject, IReadOnlyDictionary<CborObject, CborObject>
{
    private readonly List<KeyValuePair<CborObject, CborObject>> _items;

    public CborMap()
    {
        _items = new();
    }

    public CborMap(int capacity)
    {
        _items = new(capacity);
    }

    public override CborType Type => CborType.Map;

    public int Count => _items.Count;

    public IEnumerable<CborObject> Keys
    {
        get
        {
            foreach (var item in _items)
            {
                yield return item.Key;
            }
        }
    }

    public IEnumerable<CborObject> Values
    {
        get
        {
            foreach (var item in _items)
            {
                yield return item.Value;
            }
        }
    }       

    public void Add(string key, CborObject value)
    {
        _items.Add(new (new CborTextString(key), value));
    }

    public void Add(string key, bool value)
    {
        _items.Add(new(new CborTextString(key), (CborBoolean)value));
    }

    public void Add(long key, CborObject value)
    {
        _items.Add(new (new CborInteger(key), value));
    }

    public void Add(long key, byte[] value)
    {
        _items.Add(new(new CborInteger(key), new CborByteString(value)));
    }

    public void Add(long key, string value)
    {
        _items.Add(new(new CborInteger(key), new CborTextString(value)));
    }

    public void Add(long key, long value)
    {
        _items.Add(new(new CborInteger(key), new CborInteger(value)));
    }

    public void Add(string key, int value)
    {
        _items.Add(new(new CborTextString(key), new CborInteger(value)));
    }

    public void Add(string key, string value)
    {
        _items.Add(new(new CborTextString(key), new CborTextString(value)));
    }

    public void Add(string key, byte[] value)
    {
        _items.Add(new(new CborTextString(key), new CborByteString(value)));
    }

    internal void Add(CborObject key, CborObject value)
    {
        _items.Add(new (key, value));
    }

    internal void Add(string key, COSE.Algorithm value)
    {
        _items.Add(new(new CborTextString(key), new CborInteger((int)value)));
    }

    internal void Add(COSE.KeyCommonParameter key, COSE.KeyType value)
    {
        _items.Add(new(new CborInteger((int)key), new CborInteger((int)value)));
    }

    internal void Add(COSE.KeyCommonParameter key, COSE.Algorithm value)
    {
        _items.Add(new(new CborInteger((int)key), new CborInteger((int)value)));
    }

    internal void Add(COSE.KeyTypeParameter key, COSE.EllipticCurve value)
    {
        _items.Add(new(new CborInteger((int)key), new CborInteger((int)value)));
    }

    internal void Add(COSE.KeyTypeParameter key, byte[] value)
    {
        _items.Add(new(new CborInteger((int)key), new CborByteString(value)));
    }

    public bool ContainsKey(CborObject key)
    {
        foreach (var (k, _) in _items)
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
        return _items.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return _items.GetEnumerator();
    }

    internal CborObject this[COSE.KeyCommonParameter key] => GetValue((long)key);

    internal CborObject this[COSE.EllipticCurve key] => GetValue((long)key);

    internal CborObject this[COSE.KeyType key] => GetValue((long)key);

    internal CborObject this[COSE.KeyTypeParameter key] => GetValue((long)key);

    public CborObject GetValue(long key)
    {
        foreach (var item in _items)
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
#pragma warning disable CS8766
        get
        {
            foreach (var item in _items)
            {
                if (item.Key.Equals(key))
                {
                    return item.Value;
                }
            }

            return null;
        }
#pragma warning restore CS8766
    }

    public override CborObject? this[string name]
    {
        get
        {
            foreach (var item in _items)
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
        for (int i = 0; i < _items.Count; i++)
        {
            if (_items[i].Key is CborTextString textKey && textKey.Value.Equals(key, StringComparison.Ordinal))
            {
                _items.RemoveAt(i);

                return;
            }
        }
    }

    internal void Set(string key, CborObject value)
    {
        for (int i = 0; i < _items.Count; i++)
        {
            if (_items[i].Key is CborTextString textKey && textKey.Value.Equals(key, StringComparison.Ordinal))
            {
                _items[i] = new KeyValuePair<CborObject, CborObject>(new CborTextString(key), value);

                return;
            }
        }

        _items.Add(new(new CborTextString(key), value));
    }
}
