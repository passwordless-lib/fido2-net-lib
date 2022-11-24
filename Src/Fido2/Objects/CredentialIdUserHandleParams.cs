namespace Fido2NetLib.Objects;

/// <summary>
/// Paramters used for callback function
/// </summary>
public sealed class IsUserHandleOwnerOfCredentialIdParams
{   
    public IsUserHandleOwnerOfCredentialIdParams(byte[] credentialId, byte[] userHandle)
    {
        CredentialId = credentialId;
        UserHandle = userHandle;
    }

    public byte[] UserHandle { get; }

    public byte[] CredentialId { get; }
}
