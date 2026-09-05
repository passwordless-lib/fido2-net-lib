using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorClientPinResponse
{
    /// <summary>
    /// Authenticator key agreement public key in COSE_Key format.
    /// This will be used to establish a sharedSecret between platform and the authenticator.
    /// The COSE_Key-encoded public key MUST contain the optional "alg" parameter and MUST NOT contain any other optional parameters.
    /// The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
    /// </summary>
    [CborMember(0x01)]
    public CredentialPublicKey? KeyAgreement { get; set; }

    /// <summary>
    /// Encrypted pinToken using sharedSecret to be used in subsequent authenticatorMakeCredential and authenticatorGetAssertion operations.
    /// </summary>
    [CborMember(0x02)]
    public byte[]? PinToken { get; set; }

    /// <summary>
    /// Number of PIN attempts remaining before lockout.
    /// This is optionally used to show in UI when collecting the PIN in Setting a new PIN, Changing existing PIN and Getting pinToken from the authenticator flows.
    /// </summary>
    [CborMember(0x03)]
    public int? Retries { get; set; }

    /// <summary>
    /// Present and true if the authenticator requires a power cycle before any future PIN
    /// operation. Only valid in response to a getPINRetries request.
    /// </summary>
    [CborMember(0x04)]
    public bool? PowerCycleState { get; set; }

    /// <summary>
    /// Number of built-in user verification attempts remaining before lockout.
    /// </summary>
    [CborMember(0x05)]
    public int? UVRetries { get; set; }

    public static AuthenticatorClientPinResponse FromCborObject(CborObject cbor)
    {
        var result = new AuthenticatorClientPinResponse();

        foreach (var (key, value) in (CborMap)cbor)
        {
            switch ((int)key)
            {
                case 0x01:
                    result.KeyAgreement = new CredentialPublicKey((CborMap)value);
                    break;
                case 0x02:
                    result.PinToken = (byte[])value;
                    break;
                case 0x03:
                    result.Retries = (int)value;
                    break;
                case 0x04:
                    result.PowerCycleState = (bool)value;
                    break;
                case 0x05:
                    result.UVRetries = (int)value;
                    break;
            }
        }

        return result;
    }
}
