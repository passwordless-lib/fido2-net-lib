namespace Fido2NetLib.Objects;

/// <summary>
/// Parameters used for callback function
/// </summary>
public sealed class IsUserHandleOwnerOfCredentialIdParams(byte[] credentialId, byte[] userHandle)
{
    public byte[] UserHandle { get; } = userHandle;

    public byte[] CredentialId { get; } = credentialId;
}
