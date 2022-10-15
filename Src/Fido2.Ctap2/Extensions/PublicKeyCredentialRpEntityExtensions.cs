using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

internal static class PublicKeyCredentialRpEntityExtensions
{
    public static CborMap ToCborObject(this PublicKeyCredentialRpEntity rp)
    {
        var result = new CborMap {
            { "id", rp.Id },
            { "name", rp.Name }
        };

        if (rp.Icon is string icon)
        {
            result.Add("icon", icon);
        }      

        return result;
    }
}
