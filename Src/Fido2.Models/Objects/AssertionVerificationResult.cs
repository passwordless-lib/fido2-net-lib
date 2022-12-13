namespace Fido2NetLib.Objects;

/// <summary>
/// Result of the MakeAssertion verification
/// </summary>
public class AssertionVerificationResult : Fido2ResponseBase
{
    public byte[] CredentialId { get; set; }

    public uint Counter { get; set; }

    /// <summary>
    /// The latest value of the signature counter in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public uint SignCount { get; set; }
    /// <summary>
    /// The latest value of the BS flag in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public bool BS { get; set; }
    /// <summary>
    /// 
    /// </summary>
    public byte[] DevicePublicKey { get; set; }
}
