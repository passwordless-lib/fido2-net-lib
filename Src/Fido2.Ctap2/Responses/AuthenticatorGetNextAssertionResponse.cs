using System.ComponentModel.DataAnnotations;

using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorGetNextAssertionResponse
{
    /// <summary>
    /// PublicKeyCredentialDescriptor structure containing the credential identifier whose private key was used to generate the assertion.
    /// May be omitted if the allowList has exactly one Credential.
    /// </summary>
    [CborMember(0x01)]
    public PublicKeyCredentialDescriptor? Credential { get; set; }

#nullable disable

    /// <summary>
    /// The signed-over contextual bindings made by the authenticator, as specified in [WebAuthn].
    /// </summary>
    [CborMember(0x02), Required]
    public byte[] AuthData { get; set; }

    /// <summary>
    /// The assertion signature produced by the authenticator, as specified in [WebAuthn].
    /// </summary>
    [CborMember(0x03), Required]
    public byte[] Signature { get; set; }

#nullable enable

    /// <summary>
    /// PublicKeyCredentialUserEntity structure containing the user account information.
    /// User identifiable information(name, DisplayName, icon) MUST not be returned if user verification is not done by the authenticator.
    /// </summary>
    [CborMember(0x04)]
    public PublicKeyCredentialUserEntity? User { get; set; }

    public static AuthenticatorGetNextAssertionResponse FromCborObject(CborObject cbor)
    {
        var result = new AuthenticatorGetNextAssertionResponse();

        foreach (var (key, value) in (CborMap)cbor)
        {
            switch ((int)key)
            {
                case 0x01:
                    result.Credential = CborHelper.DecodePublicKeyCredentialDescriptor((CborMap)value);
                    break;
                case 0x02:
                    result.AuthData = (byte[])value;
                    break;
                case 0x03:
                    result.Signature = (byte[])value;
                    break;
                case 0x04:
                    result.User = CborHelper.DecodePublicKeyCredentialUserEntity((CborMap)value);
                    break;
            }
        }

        return result;
    }
}
