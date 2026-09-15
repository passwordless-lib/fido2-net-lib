using System.Security.Cryptography;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers the <c>largeBlob</c> extension as WebAuthn Level 3 §10.1.5 defines it: <c>read</c> and
/// <c>write</c> belong only to an assertion, <c>support</c> only to a registration, a write names exactly
/// one credential, and neither the blob nor the request carries a size limit.
/// </summary>
public class L3LargeBlobRegistrationTests : Fido2Tests.Attestation
{
    public L3LargeBlobRegistrationTests()
    {
        _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborMap() } };
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
    }

    private Task<RegisteredPublicKeyCredential> RegisterAsync(AuthenticationExtensionsLargeBlobInputs largeBlob) =>
        MakeAttestationResponseAsync(new AuthenticationExtensionsClientInputs { LargeBlob = largeBlob });

    [Fact]
    public async Task ReadIsRejectedEvenWithoutSupportAsync()
    {
        // "If read or write is present: return a DOMException whose name is NotSupportedError." The rule
        // does not depend on support being given, which is what the check used to be conditioned on.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => RegisterAsync(new AuthenticationExtensionsLargeBlobInputs { Read = true }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("'read'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WriteIsRejectedEvenWithoutSupportAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => RegisterAsync(new AuthenticationExtensionsLargeBlobInputs { Write = [0xca, 0xfe] }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("'write'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnEmptyWriteIsStillPresentAsync()
    {
        // "is present", not "is non-empty".
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => RegisterAsync(new AuthenticationExtensionsLargeBlobInputs { Write = [] }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(LargeBlobSupport.Preferred)]
    [InlineData(LargeBlobSupport.Required)]
    public async Task SupportIsTheOnlyMemberARegistrationAcceptsAsync(LargeBlobSupport? support)
    {
        // support is itself optional: "Otherwise (i.e. support is absent or has the value preferred)".
        var credential = await RegisterAsync(new AuthenticationExtensionsLargeBlobInputs { Support = support });

        Assert.Equal(_credentialID, credential.Id);
    }
}

public class L3LargeBlobAssertionTests
{
    private static Task<VerifyAssertionResult> AssertAsync(
        AuthenticationExtensionsLargeBlobInputs largeBlob,
        IReadOnlyList<PublicKeyCredentialDescriptor> allowCredentials = null) =>
        L3AssertionHarness.AssertAsync(
            new AuthenticationExtensionsClientInputs { LargeBlob = largeBlob },
            allowCredentials: allowCredentials);

    [Fact]
    public async Task SupportIsRejectedDuringAssertionAsync()
    {
        // "If support is present: return a DOMException whose name is NotSupportedError."
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => AssertAsync(new AuthenticationExtensionsLargeBlobInputs { Support = LargeBlobSupport.Required }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("'support'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadAndWriteTogetherAreRejectedAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => AssertAsync(new AuthenticationExtensionsLargeBlobInputs { Read = true, Write = [0xca, 0xfe] }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
    }

    [Fact]
    public async Task WriteRequiresExactlyOneAllowedCredentialAsync()
    {
        // "If write is present: if allowCredentials does not contain exactly one element, return a
        //  DOMException whose name is NotSupportedError."
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => AssertAsync(
                new AuthenticationExtensionsLargeBlobInputs { Write = [0xca, 0xfe] },
                [new PublicKeyCredentialDescriptor(L3AssertionHarness.CredentialId), new PublicKeyCredentialDescriptor([0xbe, 0xef])]));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("exactly one credential", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WriteWithOneAllowedCredentialIsAcceptedAsync()
    {
        var result = await AssertAsync(new AuthenticationExtensionsLargeBlobInputs { Write = [0xca, 0xfe] });

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task ABlobLargerThanSixtyFourKilobytesIsAcceptedAsync()
    {
        // The extension states no size limit; an authenticator that cannot store the blob reports
        // written=false, which is the Relying Party's to interpret.
        var result = await AssertAsync(new AuthenticationExtensionsLargeBlobInputs
        {
            Write = RandomNumberGenerator.GetBytes(65_537)
        });

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task NeitherReadNorWriteIsAcceptedAsync()
    {
        // Only the three NotSupportedError conditions are errors; asking for neither is not among them.
        var result = await AssertAsync(new AuthenticationExtensionsLargeBlobInputs());

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task ReadAloneIsAcceptedAsync()
    {
        var result = await AssertAsync(new AuthenticationExtensionsLargeBlobInputs { Read = true });

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }
}
