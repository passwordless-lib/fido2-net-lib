using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers the id/rawId cross-check, the allowCredentials membership check, and the extension
/// input/output validation branches of <see cref="AuthenticatorAssertionResponse"/>'s <c>VerifyAsync</c> that
/// <see cref="L3AssertionUserHandleTests"/> and <see cref="L3LargeBlobAssertionTests"/> don't reach.
/// </summary>
public class L3AssertionResponseValidationTests
{
    [Fact]
    public async Task AnIdThatIsNotValidBase64UrlIsRejectedAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(null, id: "not valid base64url!!"));

        Assert.Equal(Fido2ErrorCode.InvalidAssertionResponse, ex.Code);
    }

    [Fact]
    public async Task AnIdThatDoesNotDecodeToRawIdIsRejectedAsync()
    {
        // "8dA" is valid base64url, but it doesn't decode to the harness' CredentialId ([0xf1, 0xd0]) --
        // tests the mismatch branch of the id/rawId cross-check, not just the malformed-base64url one.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(null, id: "8dA", rawId: [0xbe, 0xef]));

        Assert.Equal(Fido2ErrorCode.InvalidAssertionResponse, ex.Code);
    }

    [Fact]
    public async Task ACredentialIdNotInAllowCredentialsIsRejectedAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                null,
                allowCredentials: [new PublicKeyCredentialDescriptor([0xbe, 0xef])]));

        Assert.Equal(Fido2ErrorCode.InvalidAssertionResponse, ex.Code);
        Assert.Contains("allowed credentials", ex.Message, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AnInvalidCredentialProtectionPolicyInputIsRejectedAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                new AuthenticationExtensionsClientInputs { CredentialProtectionPolicy = (CredentialProtectionPolicy)99 }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("credentialProtectionPolicy", ex.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task AValidCredentialProtectionPolicyInputIsAcceptedAsync()
    {
        var result = await L3AssertionHarness.AssertAsync(
            new AuthenticationExtensionsClientInputs { CredentialProtectionPolicy = CredentialProtectionPolicy.UserVerificationRequired });

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task AnInvalidCredentialProtectionPolicyOutputIsRejectedAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                new AuthenticationExtensionsClientInputs { CredentialProtectionPolicy = CredentialProtectionPolicy.UserVerificationRequired },
                new AuthenticationExtensionsClientOutputs { CredProtect = (CredentialProtectionPolicy)99 }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("credentialProtectionPolicy", ex.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task AValidCredentialProtectionPolicyOutputIsAcceptedAsync()
    {
        var result = await L3AssertionHarness.AssertAsync(
            new AuthenticationExtensionsClientInputs { CredentialProtectionPolicy = CredentialProtectionPolicy.UserVerificationRequired },
            new AuthenticationExtensionsClientOutputs { CredProtect = CredentialProtectionPolicy.UserVerificationRequired });

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

#pragma warning disable CS0618 // exts was removed in L3; still honoured for Level 2 callers
    [Fact]
    public async Task AnExtsDiscoveryOutputIsValidatedWhenRequestedAsync()
    {
        // Reaches ClientExtensionValidation.ValidateExtensionsDiscoveryOutput via the assertion ceremony;
        // an empty array is a well-formed (if uninteresting) discovery result.
        var result = await L3AssertionHarness.AssertAsync(
            new AuthenticationExtensionsClientInputs { Extensions = true },
            new AuthenticationExtensionsClientOutputs { Extensions = [] });

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }
#pragma warning restore CS0618

    [Fact]
    public async Task ALargeBlobSupportedOutputDuringAssertionIsRejectedAsync()
    {
        // 'supported' is a registration-only large-blob output member.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                new AuthenticationExtensionsClientInputs { LargeBlob = new AuthenticationExtensionsLargeBlobInputs { Read = true } },
                new AuthenticationExtensionsClientOutputs { LargeBlob = new AuthenticationExtensionsLargeBlobOutputs { Supported = true } }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("'supported'", ex.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task ALargeBlobOutputWithNeitherReadNorWriteRequestedIsRejectedWhenItCarriesABlobAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(
                new AuthenticationExtensionsClientInputs { LargeBlob = new AuthenticationExtensionsLargeBlobInputs() },
                new AuthenticationExtensionsClientOutputs { LargeBlob = new AuthenticationExtensionsLargeBlobOutputs { Blob = [0xca, 0xfe] } }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
    }

    [Fact]
    public async Task ALargeBlobReadOutputMatchingTheRequestIsAcceptedAsync()
    {
        // requestedRead is true, so a 'blob' in the output is expected rather than rejected -- reaches
        // the output validator's happy path (neither of its two throw conditions).
        var result = await L3AssertionHarness.AssertAsync(
            new AuthenticationExtensionsClientInputs { LargeBlob = new AuthenticationExtensionsLargeBlobInputs { Read = true } },
            new AuthenticationExtensionsClientOutputs { LargeBlob = new AuthenticationExtensionsLargeBlobOutputs { Blob = [0xca, 0xfe] } });

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }
}
