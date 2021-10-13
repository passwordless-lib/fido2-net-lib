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

            Assert.True(element[4].IsBinary);

            Assert.True(element[6].IsSequence);

            Assert.Equal(new[] { 701, 709 }, element[6].Sequence.Select(element => element.TagValue).ToArray());
        }
    }
}
