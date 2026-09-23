namespace Fido2NetLib.Objects;

/// <summary>
/// Parameters for the callback that checks whether a credential ID is already registered.
/// </summary>
/// <remarks>
/// See <see cref="IsCredentialIdUniqueToUserAsyncDelegate"/> for what the callback is being asked: step 26
/// of WebAuthn Level 3 §7.1 is about any user, not only a different one.
/// </remarks>
public sealed class IsCredentialIdUniqueToUserParams(byte[] credentialId, Fido2User user)
{
    /// <summary>
    /// The credential ID the authenticator just created, which must not already be registered.
    /// </summary>
    public byte[] CredentialId { get; } = credentialId;

    /// <summary>
    /// The user the ceremony is registering the credential to.
    /// </summary>
    public Fido2User User { get; } = user;
}
