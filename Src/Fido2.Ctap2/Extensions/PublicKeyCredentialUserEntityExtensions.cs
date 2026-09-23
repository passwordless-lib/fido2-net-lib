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

        // The icon member is [Obsolete] but CTAP2 still round-trips whatever an authenticator sends.
#pragma warning disable CS0618
        if (user.Icon is string icon)
        {
            result.Add("icon", icon);
        }
#pragma warning restore CS0618

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
