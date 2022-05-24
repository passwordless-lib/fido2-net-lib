using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

internal static class PubKeyCredParamExtensions
{
    public static CborMap ToCborObject(this PubKeyCredParam obj)
    {
        return new CborMap {
            { "alg", (int) obj.Alg },
            { "type", "public-key" }
        };
    }
}


public static class AuthenticatorTransportExtensions
{
    public static string Canonicalize(this AuthenticatorTransport value)
    {
        return value switch
        {
            AuthenticatorTransport.Usb      => "usb",
            AuthenticatorTransport.Nfc      => "nfc",
            AuthenticatorTransport.Ble      => "ble",
            AuthenticatorTransport.Internal => "internal",
            _                               => value.ToString()
        };
    }
}
