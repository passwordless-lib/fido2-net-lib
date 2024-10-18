namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorGetInfoCommand : CtapCommand
{
    public override CtapCommandType Type => CtapCommandType.AuthenticatorGetInfo;
}
