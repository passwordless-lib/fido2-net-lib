namespace Fido2NetLib.Objects
{
    /// <summary>
    /// Paramters used for callback function to check that the CredentialId is unique user
    /// </summary>
    public class IsCredentialIdUniqueToUserUserParams
    {
        public byte[] CredentialId { get; set; }
        public User User { get; set; }

        public IsCredentialIdUniqueToUserUserParams(byte[] credentialId, User user)
        {
            CredentialId = credentialId;
            User = user;
        }
    }
}
