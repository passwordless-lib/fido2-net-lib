using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorGetAssertionResponse
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
    /// User identifiable information (name, DisplayName, icon) MUST not be returned if user verification is not done by the authenticator.
    /// </summary>
    [CborMember(0x04)]
    public PublicKeyCredentialUserEntity? User { get; set; }

    /// <summary>
    /// Total number of account credentials for the RP.This member is required when more than one account for the RP and the authenticator does not have a display.
    /// Omitted when returned for the authenticatorGetNextAssertion method.
    /// </summary>
    [CborMember(0x05)]
    public int? NumberOfCredentials { get; set; }

    /// <summary>
    /// Indicates that a credential was selected by the user via interaction directly with the authenticator, and thus the platform does not need to confirm the credential.
    /// MUST NOT be present in response to a request where an allowList was given, where numberOfCredentials is greater than one, nor in response to an authenticatorGetNextAssertion request.
    /// </summary>
    [CborMember(0x06)]
    [DefaultValue(false)]
    public bool? UserSelected { get; set; }

    /// <summary>
    /// The contents of the associated largeBlobKey if present for the asserted credential, and if largeBlobKey was true in the extensions input.
    /// </summary>
    [CborMember(0x07)]
    [DefaultValue(false)]
    public byte[]? LargeBlobKey { get; set; }

    public static AuthenticatorGetAssertionResponse FromCborObject(CborObject cbor)
    {
        var result = new AuthenticatorGetAssertionResponse();

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
                case 0x05:
                    result.NumberOfCredentials = (int)value;
                    break;
                case 0x06:
                    result.UserSelected = (bool)value;
                    break;
                case 0x07:
                    result.LargeBlobKey = (byte[])value;
                    break;
            }
        }

        return result;
    }
}
