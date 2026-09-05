namespace Fido2NetLib.Ctap2;

/// <summary>
/// Request for the authenticatorSelection (0x0B) command, letting the platform ask a user to
/// select a specific authenticator (among several) by requesting user presence.
/// <para>New in CTAP 2.1 (see §6.9 of the CTAP 2.3 Proposed Standard). Takes no parameters.</para>
/// </summary>
public sealed class AuthenticatorSelectionCommand : CtapCommand
{
    public override CtapCommandType Type => CtapCommandType.AuthenticatorSelection;
}
