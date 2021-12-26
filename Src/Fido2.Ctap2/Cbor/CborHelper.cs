using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

internal sealed class CborHelper
{
    public static PublicKeyCredentialDescriptor DecodePublicKeyCredentialDescriptor(CborMap map)
    {
        var result = new PublicKeyCredentialDescriptor();

        foreach (var (key, value) in map)
        {
            switch ((string)key)
            {
                case "id":
                    result.Id = (byte[])value;
                    break;
                case "type" when (value is CborTextString { Value: "public-key" }):
                    result.Type = PublicKeyCredentialType.PublicKey;
                    break;
            }
        }

        return result;
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
                    result.Icon = (string)value;
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
