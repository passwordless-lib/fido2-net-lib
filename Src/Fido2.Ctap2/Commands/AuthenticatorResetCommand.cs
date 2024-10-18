namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorResetCommand : CtapCommand
{
    public override CtapCommandType Type => CtapCommandType.AuthenticatorReset;
}
