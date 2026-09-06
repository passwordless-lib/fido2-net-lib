using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers decoding of the authenticator extension outputs carried in the extensions block of the authenticator
/// data, which WebAuthn L3 §7.1 step 27 and §7.2 step 22 require a Relying Party to be able to process.
/// </summary>
public class L3AuthenticatorExtensionOutputTests
{
    private static AuthenticationExtensionsAuthenticatorOutputs Decode(CborMap extensions)
    {
        return new Extensions(extensions.Encode()).Outputs;
    }

    [Theory]
    [InlineData(0x01, CredentialProtectionPolicy.UserVerificationOptional)]
    [InlineData(0x02, CredentialProtectionPolicy.UserVerificationOptionalWithCredentialIdList)]
    [InlineData(0x03, CredentialProtectionPolicy.UserVerificationRequired)]
    public void CredProtectIsDecoded(int value, CredentialProtectionPolicy expected)
    {
        Assert.Equal(expected, Decode(new CborMap { { "credProtect", value } }).CredProtect);
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x04)]
    public void CredProtectOutsideTheDefinedPoliciesIsIgnored(int value)
    {
        Assert.Null(Decode(new CborMap { { "credProtect", value } }).CredProtect);
    }

    [Fact]
    public void MinPinLengthIsDecoded()
    {
        Assert.Equal(6u, Decode(new CborMap { { "minPinLength", 6 } }).MinPinLength);
    }

    [Fact]
    public void PinComplexityPolicyIsDecoded()
    {
        Assert.True(Decode(new CborMap { { "pinComplexityPolicy", true } }).PinComplexityPolicy);
    }

    [Fact]
    public void ThirdPartyPaymentIsDecoded()
    {
        Assert.False(Decode(new CborMap { { "thirdPartyPayment", false } }).ThirdPartyPayment);
    }

    [Fact]
    public void HmacSecretIsDecoded()
    {
        Assert.True(Decode(new CborMap { { "hmac-secret", true } }).HmacSecret);
    }

    [Fact]
    public void CredBlobIsABooleanOnRegistrationAndAByteStringOnAssertion()
    {
        // "credBlob": true on a registration says the authenticator stored the blob...
        var registration = Decode(new CborMap { { "credBlob", true } });

        Assert.True(registration.CredBlobStored);
        Assert.Null(registration.CredBlob);

        // ...while on an assertion the authenticator returns the blob itself.
        var assertion = Decode(new CborMap { { "credBlob", "cafe"u8.ToArray() } });

        Assert.Null(assertion.CredBlobStored);
        Assert.Equal("cafe"u8.ToArray(), assertion.CredBlob);
    }

    [Fact]
    public void OutputsWithTheWrongCborTypeAreIgnored()
    {
        var outputs = Decode(new CborMap
        {
            { "credProtect", "userVerificationRequired" },
            { "minPinLength", true },
            { "pinComplexityPolicy", 1 },
            { "hmac-secret", "yes" }
        });

        Assert.Null(outputs.CredProtect);
        Assert.Null(outputs.MinPinLength);
        Assert.Null(outputs.PinComplexityPolicy);
        Assert.Null(outputs.HmacSecret);
    }

    [Fact]
    public void UnrecognizedOutputsAreLeftToTheCaller()
    {
        var extensions = new CborMap { { "somethingNew", true } };
        var block = new Extensions(extensions.Encode());

        // Nothing this library models, but the raw block is still there to be decoded by the Relying Party.
        Assert.Null(block.Outputs.CredProtect);
        Assert.Equal(extensions.Encode(), block.GetBytes());
    }

    [Fact]
    public void AnEmptyBlockDecodesToNoOutputs()
    {
        Assert.Null(new Extensions([]).Outputs.CredProtect);
    }

    [Fact]
    public void AMalformedBlockDecodesToNoOutputs()
    {
        // A block that is not a CBOR map at all is only an error where the Relying Party asked for the outputs
        // to be validated; reading the typed outputs must not throw.
        Assert.Null(new Extensions([0xff, 0xff, 0xff]).Outputs.MinPinLength);
    }
}
