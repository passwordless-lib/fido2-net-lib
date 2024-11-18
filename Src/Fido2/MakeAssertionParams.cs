using System.ComponentModel;

namespace Fido2NetLib;

/// <summary>
/// Wraps the input for the MakeAssertion function
/// </summary>
public sealed class MakeAssertionParams
{
    /// <summary>
    /// The assertion response from the authenticator.
    /// </summary>
    public required AuthenticatorAssertionRawResponse AssertionResponse { get; init; }

    /// <summary>
    /// The original options that was sent to the client.
    /// </summary>
    public required AssertionOptions OriginalOptions { get; init; }

    /// <summary>
    /// The stored credential public key.
    /// </summary>
    public required byte[] StoredPublicKey { get; init; }

    /// <summary>
    /// The stored value of the signature counter.
    /// </summary>
    public required uint StoredSignatureCounter { get; init; }

    /// <summary>
    /// The delegate used to validate that the user handle is indeed owned of the CredentialId.
    /// </summary>
    public required IsUserHandleOwnerOfCredentialIdAsync IsUserHandleOwnerOfCredentialIdCallback { get; init; }

    /// <summary>
    /// DO NOT USE - Deprecated, but kept in code due to conformance testing tool.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public byte[]? RequestTokenBindingId { get; init; }
}
