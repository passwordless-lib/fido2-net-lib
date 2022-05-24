using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

internal static class PublicKeyCredentialUserEntityExtensions
{
    public static CborMap ToCborObject(this PublicKeyCredentialUserEntity user)
    {
        var result = new CborMap {
            { "id", user.Id }
        };

        if (user.Icon is string icon)
        {
            result.Add("icon", icon);
        }

        if (user.Name is string name)
        {
            result.Add("name", name);
        }

        if (user.DisplayName is string displayName)
        {
            result.Add("displayName", displayName);
        }

        return result;
    }
}
