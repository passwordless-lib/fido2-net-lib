namespace Fido2NetLib.Objects;

/// <summary>
/// Parameters used for callback function to check that the CredentialId is unique user
/// </summary>
public sealed class IsCredentialIdUniqueToUserParams(byte[] credentialId, Fido2User user)
{
    public byte[] CredentialId { get; } = credentialId;

    public Fido2User User { get; } = user;
}
