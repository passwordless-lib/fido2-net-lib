using System.Security.Cryptography;
using System.Text.Json;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers the WebAuthn Level 3 ceremony inputs and outputs the library's public API has to carry: <c>hints</c>
/// and <c>attestationFormats</c> on the options, <c>authenticatorAttachment</c> on the responses, conditional
/// mediation on registration, and the signal method payloads.
/// </summary>
public class L3CeremonyOptionsTests
{
    private const string Rp = "https://www.passwordless.dev";

    private static Fido2 MakeLib() => new(new Fido2Configuration
    {
        RPID = Rp,
        RPName = Rp,
        Origins = new HashSet<string> { Rp },
    });

    private static Fido2User MakeUser() => new()
    {
        Id = "testuser"u8.ToArray(),
        Name = "testuser",
        DisplayName = "Test User",
    };

    [Theory]
    [InlineData("\"platform\"", AuthenticatorAttachment.Platform)]
    [InlineData("\"cross-platform\"", AuthenticatorAttachment.CrossPlatform)]
    [InlineData("\"teleportation\"", null)]   // unknown values are treated as if absent
    [InlineData("null", null)]
    public void AuthenticatorAttachmentIsReadFromTheAttestationResponse(string attachmentJson, AuthenticatorAttachment? expected)
    {
        var json = """{"id":"AAAA","rawId":"AAAA","type":"public-key","clientExtensionResults":{},"authenticatorAttachment":"""
            + attachmentJson
            + ""","response":{"attestationObject":"AAAA","clientDataJSON":"AAAA","transports":["internal"]}}""";

        var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(json);

        Assert.Equal(expected, response.AuthenticatorAttachment);
    }

    [Fact]
    public void AuthenticatorAttachmentIsReadFromTheAssertionResponse()
    {
        var json = """
        {"id":"AAAA","rawId":"AAAA","type":"public-key","clientExtensionResults":{},"authenticatorAttachment":"cross-platform",
         "response":{"authenticatorData":"AAAA","signature":"AAAA","clientDataJSON":"AAAA"}}
        """;

        var response = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(json);

        Assert.Equal(AuthenticatorAttachment.CrossPlatform, response.AuthenticatorAttachment);
    }

    [Fact]
    public void AuthenticatorAttachmentIsOmittedWhenAbsent()
    {
        var json = """{"id":"AAAA","rawId":"AAAA","type":"public-key","clientExtensionResults":{},"response":{"attestationObject":"AAAA","clientDataJSON":"AAAA","transports":["internal"]}}""";

        var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(json);

        Assert.Null(response.AuthenticatorAttachment);
        Assert.DoesNotContain("authenticatorAttachment", JsonSerializer.Serialize(response));
    }

}
