using System;
using System.Formats.Asn1;
using System.Linq;

using Fido2NetLib;

using Xunit;

namespace Test
{
    public class Asn1Tests
    {
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

            element[0][0].EnsureTag(Asn1Tag.PrimitiveOctetString);

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

            Assert.Equal(Asn1Tag.Integer,                element[0].Tag);
            Assert.Equal(Asn1Tag.Enumerated,             element[1].Tag);
            Assert.Equal(Asn1Tag.Integer,                element[2].Tag);
            Assert.Equal(Asn1Tag.Enumerated,             element[3].Tag);
            Assert.Equal(Asn1Tag.PrimitiveOctetString,   element[4].Tag);
            Assert.Equal(Asn1Tag.PrimitiveOctetString,   element[5].Tag);
            Assert.Equal(Asn1Tag.Sequence,               element[6].Tag);
            Assert.Equal(Asn1Tag.Sequence,               element[7].Tag);

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

            var element6       = element[6];
            var element6_1     = element[6][1];
            var element6_1_0   = element[6][1][0];
            var element6_1_0_0 = element[6][1][0][0];

            Assert.True(element6.IsSequence);
            Assert.Equal(701, element6[0].TagValue);


            Assert.True(element6_1.IsConstructed);
            Assert.Equal(TagClass.ContextSpecific, element6_1.TagClass);
            Assert.Equal(1, element6_1.TagValue);
            Assert.Equal(1, element6_1.Sequence.Count);

            Assert.Equal(Asn1Tag.SetOf, element6_1_0.Tag);

            Assert.Equal(2, element6_1_0_0.TagValue);  
            Assert.Equal(1, element6_1_0_0.GetInt32());           
        }
    }
}


//  throw new Exception(string.Join(", ", element[6].Sequence.Select(element => element.TagValue)));
