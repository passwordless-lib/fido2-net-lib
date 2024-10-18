using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

internal static class PublicKeyCredentialDescriptorExtensions
{
    public static CborMap ToCborObject(this PublicKeyCredentialDescriptor obj)
    {
        return new CborMap {
            { "id",    obj.Id },
            { "type", "public-key" }
        };
    }

    public static CborArray ToCborArray(this PublicKeyCredentialDescriptor[] list)
    {
        var result = new CborArray();

        foreach (PublicKeyCredentialDescriptor item in list)
        {
            result.Add(item.ToCborObject());
        };

        return result;
    }
}
