using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;

namespace Fido2NetLib;

internal readonly struct Asn1Element
{
    private readonly Asn1Tag _tag;
    private readonly ReadOnlyMemory<byte> _encodedValue;
    private readonly List<Asn1Element>? _elements; // set | sequence

    public Asn1Element(
        Asn1Tag tag,
        ReadOnlyMemory<byte> encodedValue,
        List<Asn1Element>? elements = null)
    {
        _tag = tag;
        _encodedValue = encodedValue;
        _elements = elements;
    }

    public IReadOnlyList<Asn1Element> Sequence
    {
        get => _elements ?? (IReadOnlyList<Asn1Element>)Array.Empty<Asn1Element>();
    }

    public Asn1Element this[int index] => Sequence[index];

    public Asn1Tag Tag => _tag;

    public int TagValue => _tag.TagValue;

    public TagClass TagClass => _tag.TagClass;

    public bool IsSequence => _tag == Asn1Tag.Sequence;

    public bool IsInteger => _tag == Asn1Tag.Integer;

    public bool IsOctetString => _tag == Asn1Tag.PrimitiveOctetString;

    public bool IsConstructed => _tag.IsConstructed;

    internal static Asn1Element CreateSequence(List<Asn1Element> elements)
    {
        return new Asn1Element(Asn1Tag.Sequence, Array.Empty<byte>(), elements);
    }

    internal static Asn1Element CreateSetOf(List<Asn1Element> elements)
    {
        return new Asn1Element(Asn1Tag.SetOf, Array.Empty<byte>(), elements);
    }

    internal void CheckExactSequenceLength(int length)
    {
        if (Sequence.Count != length)
        {
            string s = length != 1 ? "s" : "";
            throw new AsnContentException($"Must have exactly {length} element{s}. Found {Sequence.Count} elements.");
        }
    }

    internal void CheckMinimumSequenceLength(int minimumLength)
    {
        if (Sequence.Count < minimumLength)
        {
            string s = minimumLength != 1 ? "s" : "";

            throw new AsnContentException($"Must have at least {minimumLength} element{s}. Found {Sequence.Count} elements.");
        }
    }

    public void CheckTag(Asn1Tag tag)
    {
        if (Tag != tag)
            throw new AsnContentException($"Tag must be {tag}. Was {Tag}");
    }

    internal void CheckConstructed()
    {
        if (!IsConstructed)
            throw new AsnContentException("Must be constructed");
    }

    internal void CheckPrimitive()
    {
        if (IsConstructed)
            throw new AsnContentException("Must be a primitive");
    }

    internal string GetOID()
    {
        return AsnDecoder.ReadObjectIdentifier(_encodedValue.Span, AsnEncodingRules.DER, out int _);
    }

    internal string GetString()
    {
        if (TagValue == (int)UniversalTagNumber.UTF8String)
        {
            return AsnDecoder.ReadCharacterString(_encodedValue.Span, AsnEncodingRules.BER, UniversalTagNumber.UTF8String, out _);
        }
        else
        {
            throw new Exception("Unknown tag: " + Tag);
        }
    }

    public BigInteger GetBigInteger()
    {
        return AsnDecoder.ReadInteger(_encodedValue.Span, AsnEncodingRules.DER, out _);
    }

    public ReadOnlySpan<byte> GetIntegerBytes()
    {
        return AsnDecoder.ReadIntegerBytes(_encodedValue.Span, AsnEncodingRules.DER, out _);
    }

    public byte[] GetOctetString()
    {
        return AsnDecoder.ReadOctetString(_encodedValue.Span, AsnEncodingRules.DER, out _);
    }

    public byte[] GetOctetString(Asn1Tag expectedTag)
    {
        return AsnDecoder.ReadOctetString(_encodedValue.Span, AsnEncodingRules.DER, out _, expectedTag);
    }

    public int GetInt32()
    {
        return AsnDecoder.TryReadInt32(_encodedValue.Span, AsnEncodingRules.BER, out int value, out int _) ? value : throw new Exception("Not an integer");
    }

    public byte[] GetBitString()
    {
        return AsnDecoder.ReadBitString(_encodedValue.Span, AsnEncodingRules.BER, out int _, out int _);
    }

    public static Asn1Element Decode(ReadOnlyMemory<byte> data)
    {
        var reader = new AsnReader(data, AsnEncodingRules.BER);

        Asn1Tag tag = reader.PeekTag();

        if (tag == Asn1Tag.Sequence)
        {
            return new Asn1Element(tag, Array.Empty<byte>(), ReadElements(reader.ReadSequence()));
        }
        else if (tag == Asn1Tag.SetOf)
        {
            return new Asn1Element(tag, Array.Empty<byte>(), ReadElements(reader.ReadSetOf()));
        }
        else if (tag.IsConstructed && tag.TagClass is TagClass.ContextSpecific)
        {
            return new Asn1Element(tag, Array.Empty<byte>(), ReadElements(reader.ReadSetOf(tag)));
        }
        else
        {
            return new Asn1Element(tag, reader.ReadEncodedValue());
        }
    }

    private static List<Asn1Element> ReadElements(AsnReader reader)
    {
        var elements = new List<Asn1Element>();

        while (reader.HasData)
        {
            Asn1Tag tag = reader.PeekTag();

            Asn1Element el;

            if (tag == Asn1Tag.Sequence)
            {
                el = new Asn1Element(tag, Array.Empty<byte>(), ReadElements(reader.ReadSequence()));
            }
            else if (tag == Asn1Tag.SetOf)
            {
                el = new Asn1Element(tag, Array.Empty<byte>(), ReadElements(reader.ReadSetOf()));
            }
            else if (tag.IsConstructed && tag.TagClass is TagClass.ContextSpecific)
            {
                el = new Asn1Element(tag, Array.Empty<byte>(), ReadElements(reader.ReadSetOf(tag)));
            }
            else
            {
                el = new Asn1Element(tag, reader.ReadEncodedValue());
            }

            elements.Add(el);
        }

        return elements;
    }
}
