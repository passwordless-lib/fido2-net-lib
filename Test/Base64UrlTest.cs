using System.Text;

using Fido2NetLib;

namespace fido2_net_lib.Test;

public class Base64UrlTest
{
    [Theory]
    [MemberData(nameof(GetData))]
    public void EncodeAndDecodeResultsAreEqual(byte[] data)
    {
        // Act
        var encodedString = Base64Url.Encode(data);
        var decodedBytes = Base64Url.Decode(encodedString);
        
        // Assert
        Assert.Equal(data, decodedBytes);

        // Ensure this also works with the Utf8 decoder
        Assert.Equal(data, Base64Url.DecodeUtf8(Encoding.UTF8.GetBytes(encodedString)));
    }

    public static IEnumerable<object[]> GetData()
    {
        return new TestDataGenerator();
    }

    private class TestDataGenerator : TheoryData<byte[]>
    {
        public TestDataGenerator()
        {
            Add("A"u8.ToArray());
            Add("This is a string fragment to test Base64Url encoding & decoding."u8.ToArray());
            Add(Array.Empty<byte>());
        }
    }

    [Fact]
    public static void Format_BadBase64Char()
    {
        const string Format_BadBase64Char = "The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters.";
        var ex = Assert.Throws<FormatException>(() => Base64Url.Decode("rCQqQMqKVO/geUyc9aENh85Mt2g1JHAUKUG27WZVE68==="));
        Assert.Equal(Format_BadBase64Char, ex.Message);

        ex = Assert.Throws<FormatException>(() => Base64Url.DecodeUtf8(Encoding.UTF8.GetBytes("rCQqQMqKVO/geUyc9aENh85Mt2g1JHAUKUG27WZVE68===")));
        Assert.Equal(Format_BadBase64Char, ex.Message);
    }
}
