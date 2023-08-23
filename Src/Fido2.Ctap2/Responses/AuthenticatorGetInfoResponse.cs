#nullable disable

using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorGetInfoResponse
{
    /// <summary>
    /// List of supported versions.Supported versions are: "FIDO_2_0" for CTAP2 / FIDO2 / Web Authentication authenticators and "U2F_V2" for CTAP1/U2F authenticators.
    /// </summary>
    [CborMember(0x01)]
    public string[] Versions { get; set; }

    /// <summary>
    /// List of supported extensions.
    /// </summary>
    [CborMember(0x02)]
    public string[] Extensions { get; set; }

    /// <summary>
    /// The claimed AAGUID. 
    /// 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in [WebAuthn].
    /// </summary>
    [CborMember(0x03)]
    public byte[] Aaguid { get; set; }

    /// <summary>
    /// List of supported options.
    /// </summary>
    [CborMember(0x04)]
    public CborMap Options { get; set; }

#nullable enable

    /// <summary>
    /// Maximum message size supported by the authenticator.
    /// </summary>
    [CborMember(0x05)]
    public int? MaxMsgSize { get; set; }

    /// <summary>
    /// List of supported PIN Protocol versions.
    /// </summary>
    [CborMember(0x06)]
    public int[]? PinProtocols { get; set; }

    public static AuthenticatorGetInfoResponse FromCborObject(CborObject cbor)
    {
        var result = new AuthenticatorGetInfoResponse();

        foreach (var (key, value) in (CborMap)cbor)
        {
            switch ((int)key)
            {
                case 0x01:
                    result.Versions = CborHelper.ToStringArray(value);
                    break;
                case 0x02:
                    result.Extensions = CborHelper.ToStringArray(value);
                    break;
                case 0x03:
                    result.Aaguid = (byte[])value;
                    break;
                case 0x04:
                    result.Options = (CborMap)value;
                    break;
                case 0x05:
                    result.MaxMsgSize = (int)value;
                    break;
                case 0x06:
                    result.PinProtocols = CborHelper.ToInt32Array(value);
                    break;
            }
        }

        return result;
    }
}
