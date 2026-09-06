namespace Fido2NetLib.Ctap2;

/// <summary>
/// Response to the authenticatorConfig (0x0D) command. The standard sub commands
/// (<see cref="AuthenticatorConfigSubCommand.EnableEnterpriseAttestation"/>,
/// <see cref="AuthenticatorConfigSubCommand.ToggleAlwaysUv"/>,
/// <see cref="AuthenticatorConfigSubCommand.SetMinPinLength"/>) return no data on success; a
/// non-OK status is surfaced as a <see cref="Fido2NetLib.Ctap2.Exceptions.CtapException"/> before this type is constructed.
/// </summary>
public sealed class AuthenticatorConfigResponse
{
}
