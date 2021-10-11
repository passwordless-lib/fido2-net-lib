using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Objects;

using Xunit;

namespace Test.Converters
{
    public class FidoEnumConverterTests
    {
        [Fact]
        public void CorrectlyUsesEnumMemberValue()
        {
            Assert.Equal("\"secure_element\"", JsonSerializer.Serialize(KeyProtection.SECURE_ELEMENT));
            Assert.Equal(KeyProtection.SECURE_ELEMENT, JsonSerializer.Deserialize<KeyProtection>("\"secure_element\""));

            Assert.Equal("\"public-key\"", JsonSerializer.Serialize(PublicKeyCredentialType.PublicKey));
            Assert.Equal(PublicKeyCredentialType.PublicKey, JsonSerializer.Deserialize<PublicKeyCredentialType>("\"public-key\""));
        }
    }
}
