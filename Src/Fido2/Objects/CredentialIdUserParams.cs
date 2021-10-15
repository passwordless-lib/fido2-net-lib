namespace Fido2NetLib.Objects
{
    /// <summary>
    /// Paramters used for callback function to check that the CredentialId is unique user
    /// </summary>
    public sealed class IsCredentialIdUniqueToUserParams
    {
        public byte[] CredentialId { get; set; }
        public Fido2User User { get; set; }

        public IsCredentialIdUniqueToUserParams(byte[] credentialId, Fido2User user)
        {
            CredentialId = credentialId;
            User = user;
        }
    }
}
