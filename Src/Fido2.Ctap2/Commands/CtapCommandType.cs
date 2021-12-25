namespace Fido2NetLib.Ctap2;

public enum CtapCommandType : byte
{
    AuthenticatorMakeCredential   = 0x01,
    AuthenticatorGetAssertion     = 0x02,
    AuthenticatorGetInfo          = 4,
    AuthenticatorClientPin        = 6,
    AuthenticatorReset            = 0x07,
    AuthenticatorGetNextAssertion = 8,
};

public static class CtapCommandTypeHelper
{
    public static string Canonicalize(this CtapCommandType command)
    {
        return command switch
        {
            CtapCommandType.AuthenticatorMakeCredential   => "authenticatorMakeCredential",
            CtapCommandType.AuthenticatorGetAssertion     => "authenticatorGetAssertion",
            CtapCommandType.AuthenticatorGetInfo          => "authenticatorGetInfo",
            CtapCommandType.AuthenticatorClientPin        => "authenticatorClientPIN",
            CtapCommandType.AuthenticatorReset            => "authenticatorReset",
            CtapCommandType.AuthenticatorGetNextAssertion => "authenticatorGetNextAssertion",

            _ => throw new Exception("Invalid command")
        };
    }
}
