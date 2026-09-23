using System.Text.Json;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers the WebAuthn Level 3 tolerances a Relying Party is expected to have towards values it did not
/// ask for: unsolicited extension outputs (§7.1 step 28) and transport hints outside
/// <see cref="AuthenticatorTransport"/> (§5.2.1).
/// </summary>
public class L3ExtensionAndTransportToleranceTests : Fido2Tests.Attestation
{
    public L3ExtensionAndTransportToleranceTests()
    {
        _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborMap() } };
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
    }

    // The harness always returns appid/exts/example/uvm client extension results, none of which are
    // requested here, so any credProps-only request is entirely unsolicited output.
    private static readonly AuthenticationExtensionsClientInputs s_credPropsOnly = new() { CredProps = true };

    [Fact]
    public async Task UnsolicitedExtensionOutputsAreIgnoredByDefaultAsync()
    {
        // WebAuthn L3 dropped Level 2's "no extensions are present that were not requested" requirement:
        // clients MAY set extensions of their own accord, and the RP chooses whether to care.
        var credential = await MakeAttestationResponseAsync(s_credPropsOnly);

        Assert.Equal(_credentialID, credential.Id);
    }

    [Fact]
    public async Task UnsolicitedExtensionOutputsAreRejectedWhenConfiguredAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(s_credPropsOnly, UnsolicitedExtensionPolicy.Reject));

        Assert.Equal(Fido2ErrorCode.UnexpectedExtensions, ex.Code);
    }

    [Fact]
    public async Task RegistrationRecordsUvInitializedFromTheUvFlagAsync()
    {
        // The harness' authenticator data sets UV.
        var credential = await MakeAttestationResponseAsync();

        Assert.True(credential.UvInitialized);
    }

    [Theory]
    [InlineData("""["usb"]""", new[] { AuthenticatorTransport.Usb })]
    [InlineData("""["internal","cable","usb"]""", new[] { AuthenticatorTransport.Internal, AuthenticatorTransport.Usb })]
    [InlineData("""["cable"]""", new AuthenticatorTransport[0])]
    [InlineData("""[]""", new AuthenticatorTransport[0])]
    public void UnknownTransportValuesAreDiscardedRatherThanRejected(string transportsJson, AuthenticatorTransport[] expected)
    {
        // getTransports() values are advisory hints; L3 says Relying Parties should accept unknown ones
        // rather than fail an otherwise valid registration.
        var json = """{"id":"AAAA","rawId":"AAAA","type":"public-key","clientExtensionResults":{},"response":{"attestationObject":"AAAA","clientDataJSON":"AAAA","transports":"""
            + transportsJson + "}}";

        var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(json);

        Assert.Equal(expected, response.Response.Transports);
    }

    [Fact]
    public void TransportsRoundTripThroughSerialization()
    {
        var json = """
        {"id":"AAAA","rawId":"AAAA","type":"public-key","clientExtensionResults":{},
         "response":{"attestationObject":"AAAA","clientDataJSON":"AAAA","transports":["usb","internal"]}}
        """;

        var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(json);

        Assert.Contains("""["usb","internal"]""", JsonSerializer.Serialize(response));
    }

    [Fact]
    public void NonStringTransportEntriesAreStillRejected()
    {
        var json = """
        {"id":"AAAA","rawId":"AAAA","type":"public-key","clientExtensionResults":{},
         "response":{"attestationObject":"AAAA","clientDataJSON":"AAAA","transports":[7]}}
        """;

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(json));
    }
}
