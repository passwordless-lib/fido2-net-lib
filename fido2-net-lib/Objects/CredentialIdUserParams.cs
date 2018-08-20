namespace Fido2NetLib.Objects
{
    /// <summary>
    /// Paramters used for callback function to check that the CredentialId is unique user
    /// </summary>
    public class IsCredentialIdUniqueToUserParams
    {
        public byte[] CredentialId { get; set; }
        public User User { get; set; }

        public IsCredentialIdUniqueToUserParams(byte[] credentialId, User user)
        {
            CredentialId = credentialId;
            User = user;
        }
    }
}
