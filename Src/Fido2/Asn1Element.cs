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

    /// <summary>
    /// The deepest nesting of constructed values <see cref="Decode"/> accepts, counting the outermost as depth 1.
    /// </summary>
    /// <remarks>
    /// Decoding recurses once per level, and so does the runtime's own search for the end of an indefinite-length
    /// value. The input is a certificate extension, which on every attestation format is the sender's to write:
    /// a few hundred kilobytes of nested SEQUENCEs overflowed the stack, which .NET cannot catch and which
    /// terminates the process. Nothing decoded here comes close -- an Android key description, the deepest,
    /// nests four levels (KeyDescription, AuthorizationList, an explicit tag, a SET OF).
    /// </remarks>
    internal const int MaxNestingDepth = 32;

    public static Asn1Element Decode(ReadOnlyMemory<byte> data)
    {
        // Before any AsnReader sees the bytes: it recurses into indefinite-length values while locating their end.
        CheckNestingDepth(data.Span);

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

    /// <summary>
    /// Walks the BER encoding iteratively, without recursing, and refuses it if constructed values nest deeper than
    /// <see cref="MaxNestingDepth"/>. Anything it cannot walk is refused too, so nothing deeper can slip past it
    /// into a decoder that does recurse -- with AsnReader's own default exception, so malformed input fails exactly
    /// as it did before.
    /// </summary>
    /// <exception cref="AsnContentException">Nested too deeply, or not well-formed BER.</exception>
    private static void CheckNestingDepth(ReadOnlySpan<byte> data)
    {
        // The end offset of each open constructed value, or -1 for one of indefinite length (ended by 00 00).
        Span<int> ends = stackalloc int[MaxNestingDepth];
        int depth = 0;
        int position = 0;

        // Only the first value is walked: Decode reads one value and ignores whatever follows it.
        do
        {
            if (position >= data.Length)
                throw new AsnContentException();

            if (depth > 0 && ends[depth - 1] is -1 && data[position] is 0)
            {
                if (position + 1 >= data.Length || data[position + 1] is not 0)
                    throw new AsnContentException();

                position += 2;
                depth--;
                depth = CloseFinished(ends, depth, position);
                continue;
            }

            // Identifier octets: the low five bits all set means the tag number continues in later octets.
            bool constructed = (data[position] & 0x20) != 0;
            bool highTagNumber = (data[position] & 0x1F) == 0x1F;
            position++;

            if (highTagNumber)
            {
                while (position < data.Length && (data[position] & 0x80) != 0)
                    position++;

                position++;
            }

            if (position >= data.Length)
                throw new AsnContentException();

            // Length octets: short form, indefinite (0x80), or long form with up to four length octets.
            int lengthByte = data[position++];
            int length;

            if (lengthByte < 0x80)
            {
                length = lengthByte;
            }
            else if (lengthByte is 0x80)
            {
                length = -1;
            }
            else
            {
                int count = lengthByte & 0x7F;

                if (count > 4 || count > data.Length - position)
                    throw new AsnContentException();

                long value = 0;
                for (int i = 0; i < count; i++)
                    value = (value << 8) | data[position++];

                if (value > data.Length - position)
                    throw new AsnContentException();

                length = (int)value;
            }

            if (length > data.Length - position)
                throw new AsnContentException();

            // A definite-length value inside a definite-length container must end within it.
            if (length >= 0 && depth > 0 && ends[depth - 1] >= 0 && position + length > ends[depth - 1])
                throw new AsnContentException();

            if (constructed)
            {
                if (depth == MaxNestingDepth)
                    throw new AsnContentException($"Constructed values are nested more than {MaxNestingDepth} levels deep.");

                ends[depth++] = length is -1 ? -1 : position + length;
            }
            else
            {
                if (length is -1)
                    throw new AsnContentException();

                position += length;
            }

            depth = CloseFinished(ends, depth, position);
        }
        while (depth > 0);

        // Closes every definite-length value that ends at the current position, innermost first.
        static int CloseFinished(Span<int> ends, int depth, int position)
        {
            while (depth > 0 && ends[depth - 1] >= 0 && position >= ends[depth - 1])
            {
                if (position > ends[depth - 1])
                    throw new AsnContentException();

                depth--;
            }

            return depth;
        }
    }

    private static List<Asn1Element> ReadElements(AsnReader reader)
    {
        List<Asn1Element> elements = [];

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
