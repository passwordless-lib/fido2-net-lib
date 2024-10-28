namespace Fido2NetLib;

/// <summary>
/// Wraps the input for the MakeNewCredential function
/// </summary>
public sealed class MakeNewCredentialParams
{
    /// <summary>
    ///  The attestation response from the authenticator.
    /// </summary>
    public required AuthenticatorAttestationRawResponse AttestationResponse { get; init; }

    /// <summary>
    ///  The original options that was sent to the client.
    /// </summary>
    public required CredentialCreateOptions OriginalOptions { get; init; }

    /// <summary>
    ///  The delegate used to validate that the CredentialID is unique to this user.
    /// </summary>
    public required IsCredentialIdUniqueToUserAsyncDelegate IsCredentialIdUniqueToUserCallback { get; init; }

    /// <summary>
    ///  DO NOT USE - Deprecated, but kept in code due to conformance testing tool
    /// </summary>
    public byte[]? RequestTokenBindingId { get; init; }
}
