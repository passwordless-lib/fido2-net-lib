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

    [Fact]
    public void RequestNewCredentialCarriesHintsAndAttestationFormats()
    {
        var options = MakeLib().RequestNewCredential(new RequestNewCredentialParams
        {
            User = MakeUser(),
            Hints = [PublicKeyCredentialHint.SecurityKey, PublicKeyCredentialHint.Hybrid],
            AttestationFormats = [AttestationStatementFormatIdentifier.Packed, AttestationStatementFormatIdentifier.None],
        });

        Assert.Equal([PublicKeyCredentialHint.SecurityKey, PublicKeyCredentialHint.Hybrid], options.Hints);
        Assert.Equal([AttestationStatementFormatIdentifier.Packed, AttestationStatementFormatIdentifier.None], options.AttestationFormats);

        var json = options.ToJson();
        Assert.Contains("\"hints\":[\"security-key\",\"hybrid\"]", json);
        Assert.Contains("\"attestationFormats\":[\"packed\",\"none\"]", json);
    }

    [Fact]
    public void GetAssertionOptionsCarriesHints()
    {
        var options = MakeLib().GetAssertionOptions(new GetAssertionOptionsParams
        {
            Hints = [PublicKeyCredentialHint.ClientDevice],
        });

        Assert.Equal([PublicKeyCredentialHint.ClientDevice], options.Hints);
        Assert.Contains("\"hints\":[\"client-device\"]", options.ToJson());
    }

    [Fact]
    public void CeremonyOptionsDefaultToNoHintsOrAttestationFormats()
    {
        var lib = MakeLib();

        Assert.Empty(lib.RequestNewCredential(new RequestNewCredentialParams { User = MakeUser() }).Hints);
        Assert.Empty(lib.RequestNewCredential(new RequestNewCredentialParams { User = MakeUser() }).AttestationFormats);
        Assert.Empty(lib.GetAssertionOptions(new GetAssertionOptionsParams()).Hints);
    }

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

    [Theory]
    [InlineData("""{"rk":true}""", true)]
    [InlineData("""{"rk":false}""", false)]
    [InlineData("""{}""", null)]
    public void CredentialPropertiesRkIsThreeState(string json, bool? expected)
    {
        // "If rk is not present, it is not known whether the credential is a discoverable credential or a
        // server-side credential" (§10.1.3), so absent must not collapse into false.
        var credProps = JsonSerializer.Deserialize<CredentialPropertiesOutput>(json);

        Assert.Equal(expected, credProps.Rk);
    }

    [Fact]
    public void SignalUnknownCredentialOptionsSerializeToTheSpecShape()
    {
        var options = MakeLib().GetUnknownCredentialOptions([0xf1, 0xd0]);

        Assert.Equal(Rp, options.RpId);
        Assert.Equal("""{"rpId":"https://www.passwordless.dev","credentialId":"8dA"}""", options.ToJson());
    }

    [Fact]
    public void SignalAllAcceptedCredentialsOptionsSerializeToTheSpecShape()
    {
        var options = MakeLib().GetAllAcceptedCredentialsOptions("testuser"u8.ToArray(), [[0xf1, 0xd0], [0x00, 0x01]]);

        Assert.Equal("""{"rpId":"https://www.passwordless.dev","userId":"dGVzdHVzZXI","allAcceptedCredentialIds":["8dA","AAE"]}""", options.ToJson());
    }

    [Fact]
    public void SignalCurrentUserDetailsOptionsSerializeToTheSpecShape()
    {
        var options = MakeLib().GetCurrentUserDetailsOptions(MakeUser());

        Assert.Equal("""{"rpId":"https://www.passwordless.dev","userId":"dGVzdHVzZXI","name":"testuser","displayName":"Test User"}""", options.ToJson());
    }
}

/// <summary>
/// Conditional mediation relaxes the user presence requirement on registration, so it needs a full ceremony.
/// </summary>
public class L3ConditionalMediationTests : Fido2Tests.Attestation
{
    public L3ConditionalMediationTests()
    {
        _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborMap() } };
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);

        // Everything the default harness sets, minus user presence.
        _flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UV;
    }

    [Fact]
    public async Task RegistrationWithoutUserPresenceIsRejectedUnderDefaultMediationAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.UserPresentFlagNotSet, ex.Code);
    }

    [Fact]
    public async Task ConditionalRegistrationWithoutUserPresenceIsAcceptedAsync()
    {
        // "If options.mediation is not set to conditional, verify that the UP bit of the flags in authData is set."
        var credential = await MakeAttestationResponseAsync(null, mediation: CredentialMediationRequirement.Conditional);

        Assert.Equal(_credentialID, credential.Id);
    }

    [Theory]
    [InlineData(CredentialMediationRequirement.Silent)]
    [InlineData(CredentialMediationRequirement.Optional)]
    [InlineData(CredentialMediationRequirement.Required)]
    public async Task OnlyConditionalMediationWaivesTheUserPresenceCheckAsync(CredentialMediationRequirement mediation)
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync(null, mediation: mediation));

        Assert.Equal(Fido2ErrorCode.UserPresentFlagNotSet, ex.Code);
    }

    [Fact]
    public async Task ConditionalRegistrationStillEnforcesTheOtherFlagChecksAsync()
    {
        // Waiving user presence must not waive anything else: drop attested credential data too.
        _flags = AuthenticatorFlags.ED | AuthenticatorFlags.UV;

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => MakeAttestationResponseAsync(null, mediation: CredentialMediationRequirement.Conditional));

        Assert.Equal(Fido2ErrorCode.AttestedCredentialDataFlagNotSet, ex.Code);
    }
}
