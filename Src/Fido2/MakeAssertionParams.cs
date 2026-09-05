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
    /// The value of the BE flag recorded when this credential was registered
    /// (<see cref="Fido2NetLib.Objects.RegisteredPublicKeyCredential.IsBackupEligible"/>), or <see langword="null"/>
    /// if the Relying Party does not track backup eligibility.
    /// </summary>
    /// <remarks>
    /// Backup eligibility is a permanent property of a credential, so when a value is supplied the assertion is
    /// rejected if its BE flag differs. Supplying this is recommended for any Relying Party that stores the flag.
    /// See step 22 of <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion"/>.
    /// </remarks>
    public bool? StoredBackupEligible { get; init; }

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
