namespace Fido2NetLib.Objects
{
    /// <summary>
    /// Result of the MakeAssertion verification
    /// </summary>
    public class AssertionVerificationResult : Fido2ResponseBase
    {
        public byte[] CredentialId { get; set; }
        public uint Counter { get; set; }
    }
}
