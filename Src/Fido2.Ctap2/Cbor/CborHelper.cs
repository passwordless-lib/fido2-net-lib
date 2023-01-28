using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

internal sealed class CborHelper
{
    public static PublicKeyCredentialDescriptor DecodePublicKeyCredentialDescriptor(CborMap map)
    {
        byte[] id = null!;
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

        return new PublicKeyCredentialDescriptor(type, id);
    }

    public static PublicKeyCredentialUserEntity DecodePublicKeyCredentialUserEntity(CborMap map)
    {
        byte[] id = null!;
        string name = null!;
        string displayName = null!;
        string? icon = null;

        foreach (var (key, value) in map)
        {
            switch ((string)key)
            {
                case "id":
                    id = (byte[])value;
                    break;
                case "name":
                    name = (string)value;
                    break;
                case "displayName":
                    displayName = (string)value;
                    break;
                case "icon":
                    icon = (string)value;
                    break;
            }
        }

        return new PublicKeyCredentialUserEntity(id, name, displayName, icon);
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
