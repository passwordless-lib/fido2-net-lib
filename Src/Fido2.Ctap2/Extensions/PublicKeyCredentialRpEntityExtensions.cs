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

        // The icon member is [Obsolete] but CTAP2 still round-trips whatever an authenticator sends.
#pragma warning disable CS0618
        if (rp.Icon is string icon)
        {
            result.Add("icon", icon);
        }
#pragma warning restore CS0618

        return result;
    }
}
