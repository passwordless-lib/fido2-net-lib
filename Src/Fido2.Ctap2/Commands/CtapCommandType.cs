namespace Fido2NetLib.Ctap2;

#pragma warning disable format
public enum CtapCommandType : byte
{
    //                                    | value    | has parameters
    AuthenticatorMakeCredential        = 0x01, // | yes
    AuthenticatorGetAssertion          = 0x02, // | yes
    AuthenticatorGetInfo               = 0x04, // | no
    AuthenticatorClientPin             = 0x06, // | yes
    AuthenticatorReset                 = 0x07, // | no
    AuthenticatorGetNextAssertion      = 0x08, // | no
    AuthenticatorBioEnrollment         = 0x09, // | yes
    AuthenticatorCredentialManagement  = 0x0A, // | yes
    AuthenticatorSelection             = 0x0B, // | no
    AuthenticatorLargeBlobs            = 0x0C, // | yes
    AuthenticatorConfig                = 0x0D, // | yes
    AuthenticatorVendorFirst           = 0x40, // | NA
    AuthenticatorVendorLast            = 0xBF, // | NA
};
