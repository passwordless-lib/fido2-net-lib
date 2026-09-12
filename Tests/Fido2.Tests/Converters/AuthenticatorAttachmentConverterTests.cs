using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Test.Converters;

/// <summary>
/// AuthenticatorAttachmentConverter is applied to the nullable authenticatorAttachment field on the raw
/// attestation/assertion response, not to the non-nullable AuthenticatorAttachment used elsewhere (e.g.
/// AuthenticatorSelection), so it has to be exercised through that DTO rather than a bare enum round-trip.
/// </summary>
public class AuthenticatorAttachmentConverterTests
{
    private sealed class Wrapper
    {
        [System.Text.Json.Serialization.JsonConverter(typeof(AuthenticatorAttachmentConverter))]
        public AuthenticatorAttachment? Value { get; set; }
    }

    [Fact]
    public void RoundTripsARecognizedValue()
    {
        var wrapper = new Wrapper { Value = AuthenticatorAttachment.Platform };

        var json = JsonSerializer.Serialize(wrapper);
        Assert.Equal("""{"Value":"platform"}""", json);

        var roundTripped = JsonSerializer.Deserialize<Wrapper>(json);
        Assert.Equal(AuthenticatorAttachment.Platform, roundTripped.Value);
    }

    [Fact]
    public void RoundTripsANullValue()
    {
        var wrapper = new Wrapper { Value = null };

        var json = JsonSerializer.Serialize(wrapper);
        Assert.Equal("""{"Value":null}""", json);

        var roundTripped = JsonSerializer.Deserialize<Wrapper>(json);
        Assert.Null(roundTripped.Value);
    }

    [Fact]
    public void MapsAnUnrecognizedStringToNull()
    {
        // WebAuthn L3: "Relying Parties SHOULD treat unknown values as if the value were null."
        var value = JsonSerializer.Deserialize<Wrapper>("""{"Value":"some-future-attachment"}""");

        Assert.Null(value.Value);
    }

    [Fact]
    public void RejectsANonStringNonNullToken()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Wrapper>("""{"Value":42}"""));
    }
}
