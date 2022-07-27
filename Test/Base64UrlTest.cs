using System;
using System.Collections.Generic;
using System.Text;
using Fido2NetLib;
using Xunit;

namespace fido2_net_lib.Test
{
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
                Add(Encoding.UTF8.GetBytes("A"));
                Add(Encoding.UTF8.GetBytes("This is a string fragment to test Base64Url encoding & decoding."));
                Add(Array.Empty<byte>());
            }
        }

        [Fact]
        public void TestBase64EncodedString()
        {
            var ex = Assert.Throws<Fido2VerificationException>(() => Base64Url.DecodeUtf8(Encoding.UTF8.GetBytes("Xvg6kAhrcnvASuXpCDw38DcIn0waPdQE8dBHDumc===")));
            Assert.True("Invalid base64url encoding" == ex.Message);
            ex = Assert.Throws<Fido2VerificationException>(() => Base64Url.DecodeUtf8(Encoding.UTF8.GetBytes("Xvg6kAhrcnvASuX+pCDw38DcIn0waPdQE8dBHDumc")));
            Assert.True("Invalid base64url encoding" == ex.Message);
            ex = Assert.Throws<Fido2VerificationException>(() => Base64Url.DecodeUtf8(Encoding.UTF8.GetBytes("Xvg6kAhrcnvASuX/pCDw38DcIn0waPdQE8dBHDumc")));
            Assert.True("Invalid base64url encoding" == ex.Message);
            Assert.NotNull(Base64Url.DecodeUtf8(Encoding.UTF8.GetBytes("Xvg6kAhrcnvASuX-pCDw38DcIn0w_aPdQ_E8dBHDumc")));
        }
    }
}
