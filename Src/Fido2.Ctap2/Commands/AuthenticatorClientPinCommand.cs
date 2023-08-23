using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorClientPinCommand : CtapCommand
{
    public AuthenticatorClientPinCommand(
        uint pinProtocol,
        AuthenticatorClientPinSubCommand subCommand,
        CredentialPublicKey? keyAgreement = null,
        byte[]? pinAuth = null,
        byte[]? newPinEnc = null,
        byte[]? pinHashEnc = null)
    {

        PinProtocol = pinProtocol;
        SubCommand = subCommand;
        KeyAgreement = keyAgreement;
        PinAuth = pinAuth;
        NewPinEnc = newPinEnc;
        PinHashEnc = pinHashEnc;
    }

    /// <summary>
    /// Required PIN protocol version chosen by the client
    /// </summary>
    [CborMember(0x01)]
    public uint PinProtocol { get; }

    /// <summary>
    /// The authenticator Client PIN sub command currently being requested.
    /// </summary>
    [CborMember(0x02)]
    public AuthenticatorClientPinSubCommand SubCommand { get; }

    /// <summary>
    /// Public key of platformKeyAgreementKey.
    /// The COSE_Key-encoded public key MUST contain the optional "alg" parameter and MUST NOT contain any other optional parameters.
    /// The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
    /// </summary>
    [CborMember(0x03)]
    public CredentialPublicKey? KeyAgreement { get; }

    /// <summary>
    /// First 16 bytes of HMAC-SHA-256 of encrypted contents using sharedSecret.
    /// </summary>
    [CborMember(0x04)]
    public byte[]? PinAuth { get; }

    /// <summary>
    /// Encrypted new PIN using sharedSecret.
    /// </summary>
    [CborMember(0x05)]
    public byte[]? NewPinEnc { get; }

    /// <summary>
    /// Encrypted first 16 bytes of SHA-256 of PIN using sharedSecret.
    /// </summary>
    [CborMember(0x06)]
    public byte[]? PinHashEnc { get; }

    public override CtapCommandType Type => CtapCommandType.AuthenticatorClientPin;

    protected override CborObject? GetParameters()
    {
        var cbor = new CborMap
        {
            { 0x01, PinProtocol },
            { 0x02, (int)SubCommand }
        };

        if (KeyAgreement != null)
        {
            cbor.Add(0x03, KeyAgreement.GetCborObject());
        }

        if (PinAuth != null)
        {
            cbor.Add(0x04, PinAuth);
        }

        if (NewPinEnc != null)
        {
            cbor.Add(0x05, NewPinEnc);
        }

        if (PinHashEnc != null)
        {
            cbor.Add(0x06, PinHashEnc);
        }

        return cbor;
    }
}

public enum AuthenticatorClientPinSubCommand
{
    GetRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
}
