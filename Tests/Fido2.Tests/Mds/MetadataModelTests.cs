using System.Text.Json;

using Fido2NetLib;

namespace Test.Mds;

/// <summary>
/// Covers the metadata model members added by Metadata Statement 3.1.1 and by the CTAP 2.3
/// <c>authenticatorGetInfo</c> structure that a metadata statement embeds.
/// </summary>
public class MetadataModelTests
{
    [Fact]
    public void BiometricAccuracyDescriptorCarriesTheIaparThreshold()
    {
        var json = """{"selfAttestedFRR":0.1,"selfAttestedFAR":0.00002,"iAPARThreshold":0.07,"maxTemplates":3,"maxRetries":5,"blockSlowdown":30}""";

        var descriptor = JsonSerializer.Deserialize<BiometricAccuracyDescriptor>(json);

        Assert.Equal(0.07, descriptor.IAPARThreshold);
        Assert.Equal(0.1, descriptor.SelfAttestedFRR);
        Assert.Equal(0.00002, descriptor.SelfAttestedFAR);
    }

    [Fact]
    public void AuthenticatorGetInfoCarriesTheCtap23Members()
    {
        var json = """
        {"versions":["FIDO_2_3"],"aaguid":"AAAA",
         "uvCountSinceLastPinEntry":2,"longTouchForReset":true,"encIdentifier":"3q2-7w",
         "transportsForReset":["usb"],"pinComplexityPolicy":true,
         "pinComplexityPolicyURL":"https://example.com/pin-policy","maxPINLength":63,
         "encCredStoreState":"3q2-7w","authenticatorConfigCommands":[1,2,255]}
        """;

        var info = JsonSerializer.Deserialize<AuthenticatorGetInfo>(json);

        Assert.Equal(2, info.UvCountSinceLastPinEntry);
        Assert.True(info.LongTouchForReset);
        Assert.Equal("3q2-7w", info.EncIdentifier);
        Assert.Equal(["usb"], info.TransportsForReset);
        Assert.True(info.PinComplexityPolicy);
        Assert.Equal("https://example.com/pin-policy", info.PinComplexityPolicyURL);
        Assert.Equal(63, info.MaxPINLength);
        Assert.Equal("3q2-7w", info.EncCredStoreState);
        Assert.Equal([1, 2, 255], info.AuthenticatorConfigCommands);
    }

    [Fact]
    public void CommandIdentifierArraysAcceptValuesWithinUInt64Range()
    {
        var json = """{"versions":["FIDO_2_3"],"vendorPrototypeConfigCommands":[18446744073709551615]}""";

        var info = JsonSerializer.Deserialize<AuthenticatorGetInfo>(json);

        Assert.Equal([ulong.MaxValue], info.VendorPrototypeConfigCommands);
    }

    [Fact]
    public void CommandIdentifierArraysClampValuesThatRoundTrippedThroughADouble()
    {
        // The FIDO conformance tools' "with configured vendor commands" metadata statement renders CBOR
        // ulong.MaxValue as 18446744073709552000 after a JavaScript double round-trip, which is technically out
        // of range for ulong (it is 385 above ulong.MaxValue).
        var json = """{"versions":["FIDO_2_3"],"vendorPrototypeConfigCommands":[18446744073709552000,184467440737095520]}""";

        var info = JsonSerializer.Deserialize<AuthenticatorGetInfo>(json);

        Assert.Equal([ulong.MaxValue, 184467440737095520UL], info.VendorPrototypeConfigCommands);
    }

    [Fact]
    public void CommandIdentifierArraysRoundTripThroughSerialization()
    {
        var info = new AuthenticatorGetInfo
        {
            VendorPrototypeConfigCommands = [1, 2, ulong.MaxValue],
        };

        var json = JsonSerializer.Serialize(info);
        var roundTripped = JsonSerializer.Deserialize<AuthenticatorGetInfo>(json);

        Assert.Equal(info.VendorPrototypeConfigCommands, roundTripped.VendorPrototypeConfigCommands);
    }

    [Fact]
    public void CommandIdentifierArraysAreNullWhenTheJsonValueIsNull()
    {
        var info = JsonSerializer.Deserialize<AuthenticatorGetInfo>("""{"vendorPrototypeConfigCommands":null}""");

        Assert.Null(info.VendorPrototypeConfigCommands);
    }

    [Fact]
    public void CommandIdentifierArraysRejectANonArrayValue()
    {
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<AuthenticatorGetInfo>("""{"vendorPrototypeConfigCommands":"not-an-array"}"""));
    }

    [Fact]
    public void CommandIdentifierArraysRejectANonNumberElement()
    {
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<AuthenticatorGetInfo>("""{"vendorPrototypeConfigCommands":[1,"two"]}"""));
    }

    [Fact]
    public void CommandIdentifierArraysAreEmptyWhenTheJsonArrayIsEmpty()
    {
        var info = JsonSerializer.Deserialize<AuthenticatorGetInfo>("""{"vendorPrototypeConfigCommands":[]}""");

        Assert.Empty(info.VendorPrototypeConfigCommands);
    }

    [Fact]
    public void CommandIdentifierArraysClampAnInRangeValueThatArrivedAsADouble()
    {
        // A decimal-formatted literal fails Utf8JsonReader.TryGetUInt64 even though its value is well within
        // ulong's range, forcing the same GetDouble()+clamp fallback as an out-of-range value -- exercising the
        // "no clamping needed" side of ClampToUInt64, as opposed to the ulong.MaxValue-saturating side.
        var json = """{"vendorPrototypeConfigCommands":[123.0]}""";

        var info = JsonSerializer.Deserialize<AuthenticatorGetInfo>(json);

        Assert.Equal([123UL], info.VendorPrototypeConfigCommands);
    }

    [Fact]
    public void AuthenticatorGetInfoWithoutTheCtap23MembersStillParses()
    {
        var info = JsonSerializer.Deserialize<AuthenticatorGetInfo>("""{"versions":["FIDO_2_0"]}""");

        Assert.Null(info.UvCountSinceLastPinEntry);
        Assert.Null(info.PinComplexityPolicy);
        Assert.Null(info.AuthenticatorConfigCommands);
    }

    [Fact]
    public void RogueListEntriesAreRead()
    {
        var json = """[{"sk":"MO-oaqbeJSSayzXaDUhh9LMKeT4Zio1bqn6W8kDaUfM","date":"2016-06-07"}]""";

        var entries = JsonSerializer.Deserialize<RogueListEntry[]>(json);

        Assert.Equal("MO-oaqbeJSSayzXaDUhh9LMKeT4Zio1bqn6W8kDaUfM", Assert.Single(entries).Sk);
        Assert.Equal("2016-06-07", entries[0].Date);
    }
}
