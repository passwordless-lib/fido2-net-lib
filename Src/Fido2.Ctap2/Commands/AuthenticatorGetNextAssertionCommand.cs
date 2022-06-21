namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorGetNextAssertionCommand : CtapCommand
{
    public override CtapCommandType Type => CtapCommandType.AuthenticatorGetNextAssertion;
}
