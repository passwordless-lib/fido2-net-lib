namespace Fido2NetLib.Ctap2;

#pragma warning disable format
public enum CtapCommandType : byte
{
    //                            | value    | has parameters
    AuthenticatorMakeCredential   = 0x01, // | yes
    AuthenticatorGetAssertion     = 0x02, // | yes
    AuthenticatorGetInfo          = 0x04, // | no
    AuthenticatorClientPin        = 0x06, // | yes
    AuthenticatorReset            = 0x07, // | no
    AuthenticatorGetNextAssertion = 0x08, // | no
    AuthenticatorVendorFirst      = 0x40, // | NA
    AuthenticatorVendorLast       = 0xBF, // | NA
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
            CtapCommandType.AuthenticatorVendorFirst      => "authenticatorVendorFirst",
            CtapCommandType.AuthenticatorVendorLast       => "authenticatorVendorLast",
            _                                             => throw new Exception("Invalid command")
        };
    }
}
