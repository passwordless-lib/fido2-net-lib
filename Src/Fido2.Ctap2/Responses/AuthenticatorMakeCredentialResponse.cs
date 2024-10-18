#nullable disable

using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorMakeCredentialResponse
{
    /// <summary>
    /// The attestation statement format identifier.
    /// </summary>
    [CborMember(0x01)]
    public string Fmt { get; set; }

    /// <summary>
    /// The authenticator data object.
    /// </summary>
    [CborMember(0x02)]
    public byte[] AuthData { get; set; }

    /// <summary>
    /// The attestation statement, whose format is identified by the "fmt" object member.
    /// The client treats it as an opaque object.
    /// </summary>
    [CborMember(0x03)]
    public CborMap AttStmt { get; set; }

    /// <summary>
    /// Indicates whether an enterprise attestation was returned for this credential.
    /// If epAtt is absent or present and set to false, then an enterprise attestation was not returned.If epAtt is present and set to true, then an enterprise attestation was returned.
    /// </summary>
    [CborMember(0x04)]
    public bool? EpAtt { get; set; }

    /// <summary>
    /// Contains the largeBlobKey for the credential, if requested with the largeBlobKey extension.
    /// </summary>
    [CborMember(0x05)]
    public byte[] LargeBlobKey { get; set; }

    public static AuthenticatorMakeCredentialResponse FromCborObject(CborObject cbor)
    {
        var result = new AuthenticatorMakeCredentialResponse();

        foreach (var (key, value) in (CborMap)cbor)
        {
            switch ((int)key)
            {
                #pragma warning disable format
                case 0x01: result.Fmt          = (string)value;  break;
                case 0x02: result.AuthData     = (byte[])value;  break;
                case 0x03: result.AttStmt      = (CborMap)value; break;
                case 0x04: result.EpAtt        = (bool)value;    break;
                case 0x05: result.LargeBlobKey = (byte[])value;  break;
                #pragma warning restore format
            }
        }

        return result;
    }
}
