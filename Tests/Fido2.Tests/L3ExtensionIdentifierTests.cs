using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers the extension identifier rules of WebAuthn Level 3 §9.1, which bound the identifiers reported by
/// the Level 2 supported extensions (<c>exts</c>) extension.
/// </summary>
public class L3ExtensionIdentifierTests : Fido2Tests.Attestation
{
    public L3ExtensionIdentifierTests()
    {
        _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborMap() } };
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
    }

#pragma warning disable CS0618 // exts was removed in L3; still honoured for Level 2 callers
    private Task<RegisteredPublicKeyCredential> RegisterAsync(string[] reportedIdentifiers)
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs { Extensions = reportedIdentifiers };

        return MakeAttestationResponseAsync(new AuthenticationExtensionsClientInputs { Extensions = true });
    }
#pragma warning restore CS0618

    [Fact]
    public async Task AnIdentifierOfThirtyTwoOctetsIsAcceptedAsync()
    {
        var credential = await RegisterAsync([new string('a', 32)]);

        Assert.Equal(_credentialID, credential.Id);
    }

    [Fact]
    public async Task AnIdentifierLongerThanThirtyTwoOctetsIsRejectedAsync()
    {
        // "All extension identifiers MUST be a maximum of 32 octets in length." The previous bound was 128,
        // which is not a number this specification uses.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => RegisterAsync([new string('a', 33)]));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("33 octets", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("has space")]
    [InlineData("has\"quote")]
    [InlineData("has\\backslash")]
    [InlineData("nonasciié")]
    public async Task AnIdentifierOutsideTheAllowedCharacterSetIsRejectedAsync(string identifier)
    {
        // "MUST consist only of printable USASCII characters, excluding backslash and doublequote."
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => RegisterAsync([identifier]));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("printable USASCII", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task AnEmptyOrWhitespaceIdentifierIsRejectedAsync(string identifier)
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => RegisterAsync([identifier]));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("empty or whitespace", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AConventionalIdentifierIsAcceptedAsync()
    {
        var credential = await RegisterAsync(["prf", "largeBlob", "myCompany_extension"]);

        Assert.Equal(_credentialID, credential.Id);
    }

    [Fact]
    public void ANullIdentifierArrayIsANoOp()
    {
        // Both call sites already guard on clientExtensionResults.Extensions != null before calling this, so
        // in practice this is defensive rather than reachable -- covered directly since the method is internal.
        ClientExtensionValidation.ValidateExtensionsDiscoveryOutput(null);
    }
}
