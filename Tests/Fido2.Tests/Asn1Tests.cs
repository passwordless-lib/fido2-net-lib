using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;

using Fido2NetLib;

namespace Test;

public class Asn1Tests
{
    [Fact]
    public void EncodeTpmSan()
    {
        Assert.Equal("MG2kazBpMRYwFAYFZ4EFAgEMC2lkOkZGRkZGMUQwMTcwNQYFZ4EFAgIMLEZJRE8yLU5FVC1MSUItVGVzdFRQTUFpa0NlcnRTQU5UQ0dDb25mb3JtYW50MRYwFAYFZ4EFAgMMC2lkOkYxRDAwMDAy", Convert.ToBase64String(TpmSanEncoder.Encode(
            (new Oid("2.23.133.2.1"), "id:FFFFF1D0"),
            (new Oid("2.23.133.2.2"), "FIDO2-NET-LIB-TestTPMAikCertSANTCGConformant"),
            (new Oid("2.23.133.2.3"), "id:F1D00002")
        )));
    }

    [Fact]
    public void DecodeObjectIdentifierAsOctetString()
    {
        byte[] data = Convert.FromBase64String("MD8wPaA7oDmGN2h0dHBzOi8vbWRzMy5jZXJ0aW5mcmEuZmlkb2FsbGlhbmNlLm9yZy9jcmwvTURTQ0EtMS5jcmw=");

        var decoded = Asn1Element.Decode(data);

        Assert.Equal(new Asn1Tag(TagClass.ContextSpecific, (int)UniversalTagNumber.ObjectIdentifier), decoded[0][0][0][0].Tag);

        var cdp = Encoding.ASCII.GetString(decoded[0][0][0][0].GetOctetString(decoded[0][0][0][0].Tag));

        Assert.Equal("https://mds3.certinfra.fidoalliance.org/crl/MDSCA-1.crl", cdp);
    }

    [Fact]
    public void DecodeEcDsaSig()
    {
        byte[] ecDsaSig = Convert.FromBase64String("MEUCIDelsTyfT/3Z6UO1KBz1j/GBoQmDN/2MXxsfGZNon1dsAiEAqsl2tTaUhnNoFTokqm4B/RegC9y5z/bSsAwtBXsQwdg=");

        var decoded = Asn1Element.Decode(ecDsaSig);

        Assert.Equal(Asn1Tag.Integer, decoded[0].Tag);
        Assert.Equal(Asn1Tag.Integer, decoded[1].Tag);

        var r = decoded[0].GetIntegerBytes();
        var s = decoded[1].GetIntegerBytes();

        Assert.Equal("N6WxPJ9P/dnpQ7UoHPWP8YGhCYM3/YxfGx8Zk2ifV2w=", Convert.ToBase64String(r));
        Assert.Equal("AKrJdrU2lIZzaBU6JKpuAf0XoAvcuc/20rAMLQV7EMHY", Convert.ToBase64String(s));


    }
    [Fact]
    public void DecodeBitString()
    {
        byte[] data = Convert.FromBase64String("AwIFIA==");

        var element = Asn1Element.Decode(data);

        Assert.Equal(Asn1Tag.PrimitiveBitString, element.Tag);

        Assert.Equal("IA==", Convert.ToBase64String(element.GetBitString()));
    }

    [Fact]
    public void DecodeConstructedObject()
    {
        byte[] data = Convert.FromBase64String("MCShIgQgnGACFUCz4Zg03+N+xiRFyJ4bKU95LORrlBPDIw7zhoE=");

        var element = Asn1Element.Decode(data);

        Assert.True(element.IsConstructed);

        element[0][0].CheckTag(Asn1Tag.PrimitiveOctetString);

        Assert.Equal("nGACFUCz4Zg03+N+xiRFyJ4bKU95LORrlBPDIw7zhoE=", Convert.ToBase64String(element[0][0].GetOctetString()));
    }

    [Fact]
    public void DecodeOctetString()
    {
        byte[] data = Convert.FromBase64String("MIHPAgECCgEAAgEBCgEABCDc0UoXtU1CwwItW3ne2faKDcFCabFI31BufXEFVK/ENwQAMGm/hT0IAgYBXtPjz6C/hUVZBFcwVTEvMC0EKGNvbS5hbmRyb2lkLmtleXN0b3JlLmFuZHJvaWRrZXlzdG9yZWRlbW8CAQExIgQgdM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2JgwMqEFMQMCAQKiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb+DeAMCAQK/hT4DAgEAv4U/AgUA");

        var element = Asn1Element.Decode(data);

        Assert.True(element[4].IsOctetString);
        Assert.Equal(Asn1Tag.PrimitiveOctetString, element[4].Tag);


        Assert.Equal("3NFKF7VNQsMCLVt53tn2ig3BQmmxSN9Qbn1xBVSvxDc=", Convert.ToBase64String(element[4].GetOctetString()));
    }

    [Fact]
    public void Decode()
    {
        byte[] data = Convert.FromBase64String("MIHPAgECCgEAAgEBCgEABCDc0UoXtU1CwwItW3ne2faKDcFCabFI31BufXEFVK/ENwQAMGm/hT0IAgYBXtPjz6C/hUVZBFcwVTEvMC0EKGNvbS5hbmRyb2lkLmtleXN0b3JlLmFuZHJvaWRrZXlzdG9yZWRlbW8CAQExIgQgdM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2JgwMqEFMQMCAQKiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb+DeAMCAQK/hT4DAgEAv4U/AgUA");

        var element = Asn1Element.Decode(data);

        Assert.Equal(Asn1Tag.Sequence, element.Tag);
        Assert.Equal(8, element.Sequence.Count);
        Assert.Equal(new[] { 2, 10, 2, 10, 4, 4, 16, 16 }, element.Sequence.Select(element => element.TagValue).ToArray());

        Assert.Equal(Asn1Tag.Integer, element[0].Tag);
        Assert.Equal(Asn1Tag.Enumerated, element[1].Tag);
        Assert.Equal(Asn1Tag.Integer, element[2].Tag);
        Assert.Equal(Asn1Tag.Enumerated, element[3].Tag);
        Assert.Equal(Asn1Tag.PrimitiveOctetString, element[4].Tag);
        Assert.Equal(Asn1Tag.PrimitiveOctetString, element[5].Tag);
        Assert.Equal(Asn1Tag.Sequence, element[6].Tag);
        Assert.Equal(Asn1Tag.Sequence, element[7].Tag);

        Assert.True(element[0].IsInteger);
        Assert.Equal(2, element[0].GetInt32());

        Assert.True(element[4].IsOctetString);

        Assert.True(element[6].IsSequence);

        Assert.Equal(new[] { 701, 709 }, element[6].Sequence.Select(element => element.TagValue).ToArray());
    }

    [Fact]
    public void DecodeContextSpecificConstructedSet()
    {
        byte[] data = Convert.FromBase64String("MGACAQMgAwQBAAIBAiADBAEABCABfDdfwPehWBVL2KIcBZflxAraVzzPoB2bIb9ZUqt97gQQ7PlbfpnmqCgDZgrEb1eHiTARv4U9BgIEYWcoF6EFMQMCAQEwB7+FPgMCAQA=");

        var element = Asn1Element.Decode(data);

        Assert.Equal(Asn1Tag.Sequence, element.Tag);
        Assert.Equal(8, element.Sequence.Count);
        Assert.Equal(new[] { 2, 0, 2, 0, 4, 4, 16, 16 }, element.Sequence.Select(element => element.TagValue).ToArray());

        var element6 = element[6];
        var element6_1 = element[6][1];
        var element6_1_0 = element[6][1][0];
        var element6_1_0_0 = element[6][1][0][0];

        Assert.True(element6.IsSequence);
        Assert.Equal(701, element6[0].TagValue);


        Assert.True(element6_1.IsConstructed);
        Assert.Equal(TagClass.ContextSpecific, element6_1.TagClass);
        Assert.Equal(1, element6_1.TagValue);
        Assert.Single(element6_1.Sequence);

        Assert.Equal(Asn1Tag.SetOf, element6_1_0.Tag);

        Assert.Equal(2, element6_1_0_0.TagValue);
        Assert.Equal(1, element6_1_0_0.GetInt32());
    }

    // SEQUENCEs nested `depth` deep around a NULL. DER writes definite lengths; CER writes indefinite ones, which the
    // runtime resolves by searching for each end-of-contents.
    private static byte[] NestedSequences(AsnEncodingRules rules, int depth)
    {
        var writer = new AsnWriter(rules);
        var scopes = new Stack<AsnWriter.Scope>();

        for (int i = 0; i < depth; i++)
            scopes.Push(writer.PushSequence());

        writer.WriteNull();

        while (scopes.Count > 0)
            scopes.Pop().Dispose();

        return writer.Encode();
    }

    [Theory]
    [InlineData(AsnEncodingRules.DER)]
    [InlineData(AsnEncodingRules.CER)]
    public void DecodeAcceptsNestingUpToTheLimit(AsnEncodingRules rules)
    {
        var element = Asn1Element.Decode(NestedSequences(rules, Asn1Element.MaxNestingDepth));

        for (int i = 1; i < Asn1Element.MaxNestingDepth; i++)
            element = element[0];

        Assert.Equal(Asn1Tag.Null, element[0].Tag);
    }

    [Theory]
    [InlineData(AsnEncodingRules.DER)]
    [InlineData(AsnEncodingRules.CER)]
    public void DecodeRefusesNestingPastTheLimit(AsnEncodingRules rules)
    {
        // Refused before any decoding starts: the check walks the encoding without recursing.
        var ex = Assert.Throws<AsnContentException>(() => Asn1Element.Decode(NestedSequences(rules, Asn1Element.MaxNestingDepth + 1)));

        Assert.Contains("nested", ex.Message);
    }

    [Fact]
    public void DecodeStillIgnoresBytesAfterTheFirstValue()
    {
        var element = Asn1Element.Decode(Convert.FromHexString("0500FFFF"));

        Assert.Equal(Asn1Tag.Null, element.Tag);
    }

    [Theory]
    [InlineData("300204050000000000")] // an OCTET STRING running past the end of the SEQUENCE holding it
    [InlineData("04800000")]           // a primitive value with an indefinite length
    [InlineData("30050500")]           // a SEQUENCE claiming more bytes than there are
    [InlineData("3080")]               // an indefinite-length SEQUENCE with no end-of-contents
    [InlineData("1F")]                 // an identifier with no length
    [InlineData("3085FFFFFFFFFF")]     // a length too large to represent
    public void DecodeRefusesMalformedStructure(string hex)
    {
        // Each of these was refused before the depth check existed too, with the same exception type -- which is
        // what callers handle; only some of the messages were more specific.
        Assert.Throws<AsnContentException>(() => Asn1Element.Decode(Convert.FromHexString(hex)));
    }
}
