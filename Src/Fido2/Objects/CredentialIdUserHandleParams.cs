namespace Fido2NetLib.Objects
{
    /// <summary>
    /// Paramters used for callback function
    /// </summary>
    public class IsUserHandleOwnerOfCredentialIdParams
    {
        public byte[] UserHandle { get; }
        public byte[] CredentialId { get; }

        public IsUserHandleOwnerOfCredentialIdParams(byte[] credentialId, byte[] userHandle)
        {
            CredentialId = credentialId;
            UserHandle = userHandle;
        }
    }
}
