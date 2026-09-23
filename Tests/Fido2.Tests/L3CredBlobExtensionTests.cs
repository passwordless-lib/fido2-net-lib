using System.Text.Json;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers the CTAP extensions that are exposed to Relying Parties through the WebAuthn client extension
/// inputs and outputs: credBlob/getCredBlob and pinComplexityPolicy.
/// </summary>
public class L3CredBlobExtensionTests : Fido2Tests.Attestation
{
    public L3CredBlobExtensionTests()
    {
        _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborMap() } };
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
    }

    [Fact]
    public void CredBlobInputsSerializeToTheSpecShape()
    {
        var registration = JsonSerializer.Serialize(new AuthenticationExtensionsClientInputs
        {
            CredBlob = [0xca, 0xfe],
            PinComplexityPolicy = true
        });

        Assert.Contains(""""credBlob":"yv4"""", registration, StringComparison.Ordinal);
        Assert.Contains(""""pinComplexityPolicy":true"""", registration, StringComparison.Ordinal);

        var assertion = JsonSerializer.Serialize(new AuthenticationExtensionsClientInputs { GetCredBlob = true });

        Assert.Contains(""""getCredBlob":true"""", assertion, StringComparison.Ordinal);
    }

    [Fact]
    public void CredBlobOutputsAreRead()
    {
        var registration = JsonSerializer.Deserialize<AuthenticationExtensionsClientOutputs>("""{"credBlob":false}""");

        Assert.False(registration.CredBlob);

        var assertion = JsonSerializer.Deserialize<AuthenticationExtensionsClientOutputs>("""{"getCredBlob":"yv4"}""");

        Assert.Equal([0xca, 0xfe], assertion.GetCredBlob);
    }

    [Fact]
    public void ExtensionsAreAbsentFromTheJsonWhenUnset()
    {
        var json = JsonSerializer.Serialize(new AuthenticationExtensionsClientInputs());

        Assert.DoesNotContain("credBlob", json, StringComparison.Ordinal);
        Assert.DoesNotContain("pinComplexityPolicy", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RegistrationAcceptsCredBlobAndPinComplexityPolicyAsync()
    {
        var credential = await MakeAttestationResponseAsync(new AuthenticationExtensionsClientInputs
        {
            CredBlob = [0xca, 0xfe],
            PinComplexityPolicy = true
        });

        Assert.NotNull(credential);
    }

    [Fact]
    public async Task RegistrationRejectsTheAssertionOnlyGetCredBlobAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(new AuthenticationExtensionsClientInputs { GetCredBlob = true }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("not valid during registration", ex.Message, StringComparison.Ordinal);
    }
}
