using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

internal sealed class CborHelper
{
    public static PublicKeyCredentialDescriptor DecodePublicKeyCredentialDescriptor(CborMap map)
    {
        byte[]? id = null;
        PublicKeyCredentialType type = default;

        foreach (var (key, value) in map)
        {
            switch ((string)key)
            {
                case "id":
                    id = (byte[])value;
                    break;
                case "type" when (value is CborTextString { Value: "public-key" }):
                    type = PublicKeyCredentialType.PublicKey;
                    break;
            }
        }

        return new PublicKeyCredentialDescriptor(type, id!, null);
    }

    public static PublicKeyCredentialRpEntity DecodePublicKeyCredentialRpEntity(CborMap map)
    {
        string? id = null;
        string? name = null;
        string? icon = null;

        foreach (var (key, value) in map)
        {
            switch ((string)key)
            {
                case "id":
                    id = (string)value;
                    break;
                case "name":
                    name = (string)value;
                    break;
                case "icon":
                    icon = (string)value;
                    break;
            }
        }

        return new PublicKeyCredentialRpEntity(id!, name ?? string.Empty, icon);
    }

    public static PublicKeyCredentialUserEntity DecodePublicKeyCredentialUserEntity(CborMap map)
    {
        var result = new PublicKeyCredentialUserEntity();

        foreach (var (key, value) in map)
        {
            switch ((string)key)
            {
                case "id":
                    result.Id = (byte[])value;
                    break;
                case "name":
                    result.Name = (string)value;
                    break;
                case "displayName":
                    result.DisplayName = (string)value;
                    break;
                case "icon":
#pragma warning disable CS0618 // obsolete, but CTAP2 round-trips whatever an authenticator sends
                    result.Icon = (string)value;
#pragma warning restore CS0618
                    break;
            }
        }

        return result;
    }

    public static string[] ToStringArray(CborObject cborObject)
    {
        var cborArray = (CborArray)cborObject;

        var result = new string[cborArray.Length];

        for (int i = 0; i < cborArray.Length; i++)
        {
            result[i] = (string)cborArray[i];
        }

        return result;
    }

    /// <summary>
    /// Decodes an array of PublicKeyCredentialParameters, as returned in the algorithms (0x0A) member
    /// of an authenticatorGetInfo response.
    /// </summary>
    public static PubKeyCredParam[] ToPubKeyCredParams(CborObject cborObject)
    {
        var cborArray = (CborArray)cborObject;

        var result = new PubKeyCredParam[cborArray.Length];

        for (int i = 0; i < cborArray.Length; i++)
        {
            var map = (CborMap)cborArray[i];

            result[i] = new PubKeyCredParam((COSE.Algorithm)(int)map["alg"]!);
        }

        return result;
    }

    public static int[] ToInt32Array(CborObject cborObject)
    {
        var cborArray = (CborArray)cborObject;

        var result = new int[cborArray.Length];

        for (int i = 0; i < cborArray.Length; i++)
        {
            result[i] = (int)cborArray[i];
        }

        return result;
    }
}
