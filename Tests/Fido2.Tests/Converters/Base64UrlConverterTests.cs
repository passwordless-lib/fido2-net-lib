using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib;

namespace Test.Converters;

public class Base64UrlConverterTests
{
    private sealed class Holder
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Value { get; set; }
    }

    [Fact]
    public void DecodesBase64Url()
    {
        var holder = JsonSerializer.Deserialize<Holder>("""{"Value":"-_8"}""");

        Assert.Equal([0xfb, 0xff], holder.Value);
    }

    [Fact]
    public void LeavesNullAlone()
    {
        var holder = JsonSerializer.Deserialize<Holder>("""{"Value":null}""");

        Assert.Null(holder.Value);
    }

    [Fact]
    public void RoundTripsThroughWriteAndRead()
    {
        byte[] value = [0x00, 0x01, 0x7f, 0x80, 0xff];

        var json = JsonSerializer.Serialize(new Holder { Value = value });
        var roundTripped = JsonSerializer.Deserialize<Holder>(json);

        Assert.Equal(value, roundTripped.Value);
    }

    [Fact]
    public void RejectsTextThatIsNotBase64Url()
    {
        // The exact wording (and which of Base64Url/Base64's own message comes through) differs between the
        // net8.0 and net10.0 BCL, so only the shared substring is asserted.
        var ex = Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Holder>("""{"Value":"not base64url!"}"""));

        Assert.Contains("is not a valid", ex.Message);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    public void RejectsTokensThatAreNotScalarValues(string token)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Holder>($$"""{"Value":{{token}}}"""));
    }

    // The converter reads whatever raw text the token carries and hands it to the base64url decoder without first
    // checking the token is actually a JSON string. A bare `true` or a number happens to decode as valid
    // base64url text (its literal characters are all in the base64url alphabet), so it is silently accepted
    // rather than rejected as a type mismatch. Documented here as the current, verified behavior -- not
    // necessarily the intended one -- so a future change to reject these is a deliberate decision, not a
    // silent regression either way.
    [Theory]
    [InlineData("true")]
    [InlineData("4639")]
    public void SilentlyDecodesNonStringScalarTokensAsBase64UrlText(string token)
    {
        var holder = JsonSerializer.Deserialize<Holder>($$"""{"Value":{{token}}}""");

        Assert.NotNull(holder.Value);
    }
}
