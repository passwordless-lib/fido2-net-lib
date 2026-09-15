using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers step 6 of WebAuthn Level 3 §7.2, which requires a user handle when the Relying Party did not
/// identify the user before starting the ceremony.
/// </summary>
public class L3AssertionUserHandleTests
{
    private static readonly PublicKeyCredentialDescriptor s_allowed =
        new(L3AssertionHarness.CredentialId);

    [Fact]
    public async Task AUsernamelessAssertionWithoutAUserHandleIsRejectedAsync()
    {
        // "If the user was not identified before the authentication ceremony was initiated, verify that
        //  response.userHandle is present." An empty allowCredentials is that case; without a user handle
        //  the credential ID alone would decide which account was signed in to.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(null, allowCredentials: [], omitUserHandle: true));

        Assert.Equal(Fido2ErrorCode.InvalidAssertionResponse, ex.Code);
        Assert.Contains("allowCredentials", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AUsernamelessAssertionWithAUserHandleIsAcceptedAsync()
    {
        var result = await L3AssertionHarness.AssertAsync(null, allowCredentials: []);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task AnAssertionThatNamedItsCredentialsDoesNotNeedAUserHandleAsync()
    {
        // The other branch of step 6: the user was identified up front, so a user handle is optional and
        // only has to match the account when the authenticator does return one.
        var result = await L3AssertionHarness.AssertAsync(null, allowCredentials: [s_allowed], omitUserHandle: true);

        Assert.Equal(L3AssertionHarness.CredentialId, result.CredentialId);
    }

    [Fact]
    public async Task AnEmptyUserHandleIsStillRejectedAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => L3AssertionHarness.AssertAsync(null, allowCredentials: [s_allowed], userHandle: []));

        Assert.Contains("empty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
