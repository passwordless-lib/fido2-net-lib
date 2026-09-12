using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Response to the authenticatorLargeBlobs (0x0C) command. Only populated in response to a
/// read (<c>get</c>) request; write (<c>set</c>) requests return an empty response on success.
/// </summary>
public sealed class AuthenticatorLargeBlobsResponse
{
    /// <summary>
    /// The requested substring of the stored serialized large-blob array.
    /// </summary>
    [CborMember(0x01)]
    public byte[]? Config { get; set; }

    public static AuthenticatorLargeBlobsResponse FromCborObject(CborObject cbor)
    {
        var result = new AuthenticatorLargeBlobsResponse();

        foreach (var (key, value) in (CborMap)cbor)
        {
            if ((int)key is 0x01)
            {
                result.Config = (byte[])value;
            }
        }

        return result;
    }
}
