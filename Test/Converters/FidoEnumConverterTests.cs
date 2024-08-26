using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Test.Converters;

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

    [Fact]
    public void CorrectlyFallsBackToMemberName()
    {
        Assert.Equal("\"A\"", JsonSerializer.Serialize(ABC.A));
        Assert.Equal(ABC.A, JsonSerializer.Deserialize<ABC>("\"A\""));
        Assert.Equal(PublicKeyCredentialType.PublicKey, JsonSerializer.Deserialize<PublicKeyCredentialType>("\"PublicKey\""));

        // Case insensitive
        Assert.Equal("\"A\"", JsonSerializer.Serialize(ABC.A));
        Assert.Equal(ABC.A, JsonSerializer.Deserialize<ABC>("\"a\""));
        Assert.Equal(PublicKeyCredentialType.PublicKey, JsonSerializer.Deserialize<PublicKeyCredentialType>("\"publickey\""));
    }

    [Fact]
    public void CorrectlyDeserializesNumericEnumValue()
    {
        Assert.Equal(CredentialProtectionPolicy.UserVerificationRequired, JsonSerializer.Deserialize<CredentialProtectionPolicy>($"{CredentialProtectionPolicy.UserVerificationRequired:d}"));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<CredentialProtectionPolicy>($"99"));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<CredentialProtectionPolicy>($"99.7"));
    }

    [Fact]
    public void DeserializationIsCaseInsensitive()
    {
        Assert.Equal("\"A\"", JsonSerializer.Serialize(ABC.A));
        Assert.Equal(ABC.A, JsonSerializer.Deserialize<ABC>("\"a\""));
    }

    [JsonConverter(typeof(FidoEnumConverter<ABC>))]
    public enum ABC
    {
        A = 1,
        B = 2,
        C = 3
    }
}
