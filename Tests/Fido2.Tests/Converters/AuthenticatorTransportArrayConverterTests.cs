using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Test.Converters;

public class AuthenticatorTransportArrayConverterTests
{
    private sealed class Wrapper
    {
        [System.Text.Json.Serialization.JsonConverter(typeof(AuthenticatorTransportArrayConverter))]
        public AuthenticatorTransport[] Value { get; set; }
    }

    [Fact]
    public void RoundTripsRecognizedTransports()
    {
        var wrapper = new Wrapper { Value = [AuthenticatorTransport.Usb, AuthenticatorTransport.Internal] };

        var json = JsonSerializer.Serialize(wrapper);
        Assert.Equal("""{"Value":["usb","internal"]}""", json);

        var roundTripped = JsonSerializer.Deserialize<Wrapper>(json);
        Assert.Equal(wrapper.Value, roundTripped.Value);
    }

    [Fact]
    public void SilentlyDropsAnUnrecognizedTransport()
    {
        // WebAuthn L3: clients may report transport values outside the enumeration, and Relying Parties
        // SHOULD accept them rather than fail the ceremony over an advisory hint.
        var value = JsonSerializer.Deserialize<Wrapper>("""{"Value":["usb","some-future-transport","ble"]}""");

        Assert.Equal([AuthenticatorTransport.Usb, AuthenticatorTransport.Ble], value.Value);
    }

    [Fact]
    public void IsNullWhenTheJsonValueIsNull()
    {
        var value = JsonSerializer.Deserialize<Wrapper>("""{"Value":null}""");

        Assert.Null(value.Value);
    }

    [Fact]
    public void IsEmptyWhenTheJsonArrayIsEmpty()
    {
        var value = JsonSerializer.Deserialize<Wrapper>("""{"Value":[]}""");

        Assert.Empty(value.Value);
    }

    [Fact]
    public void RejectsANonArrayValue()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Wrapper>("""{"Value":"usb"}"""));
    }

    [Fact]
    public void RejectsANonStringElement()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Wrapper>("""{"Value":["usb",1]}"""));
    }
}
