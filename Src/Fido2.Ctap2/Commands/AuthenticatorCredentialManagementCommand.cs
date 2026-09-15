using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Request for the authenticatorCredentialManagement (0x0A) command, used to enumerate, delete,
/// and update discoverable credentials stored on the authenticator.
/// <para>New in CTAP 2.1 (see §6.8 of the CTAP 2.3 Proposed Standard).</para>
/// </summary>
public sealed class AuthenticatorCredentialManagementCommand(
    AuthenticatorCredentialManagementSubCommand subCommand,
    CborMap? subCommandParams = null,
    uint? pinUvAuthProtocol = null,
    byte[]? pinUvAuthParam = null) : CtapCommand
{
    /// <summary>
    /// The credential management sub command currently being requested.
    /// </summary>
    [CborMember(0x01)]
    public AuthenticatorCredentialManagementSubCommand SubCommand { get; } = subCommand;

    /// <summary>
    /// Sub command specific parameters, if any.
    /// </summary>
    [CborMember(0x02)]
    public CborMap? SubCommandParams { get; } = subCommandParams;

    /// <summary>
    /// PIN/UV protocol version chosen by the platform.
    /// </summary>
    [CborMember(0x03)]
    public uint? PinUvAuthProtocol { get; } = pinUvAuthProtocol;

    /// <summary>
    /// The output of calling authenticate on some context specific to the sub command. Unlike
    /// authenticatorConfig, this is NOT prefixed with 32×0xff or the command's own opcode: it is
    /// <c>authenticate(pinUvAuthToken, subCommand || subCommandParams)</c>, where
    /// <c>subCommandParams</c> is only included, CBOR-encoded, when present.
    /// </summary>
    [CborMember(0x04)]
    public byte[]? PinUvAuthParam { get; } = pinUvAuthParam;

    public override CtapCommandType Type => CtapCommandType.AuthenticatorCredentialManagement;

    protected override CborObject? GetParameters()
    {
        var cbor = new CborMap
        {
            { 0x01, (int)SubCommand }
        };

        if (SubCommandParams != null)
        {
            cbor.Add(0x02, SubCommandParams);
        }

        if (PinUvAuthProtocol.HasValue)
        {
            cbor.Add(0x03, (int)PinUvAuthProtocol.Value);
        }

        if (PinUvAuthParam != null)
        {
            cbor.Add(0x04, PinUvAuthParam);
        }

        return cbor;
    }
}

public enum AuthenticatorCredentialManagementSubCommand
{
    #pragma warning disable format
    GetCredsMetadata                      = 0x01,
    EnumerateRPsBegin                     = 0x02,
    EnumerateRPsGetNextRP                 = 0x03,
    EnumerateCredentialsBegin             = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential                      = 0x06,
    UpdateUserInformation                 = 0x07,
    #pragma warning restore format
}
