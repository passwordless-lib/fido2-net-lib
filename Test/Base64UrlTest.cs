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
}
