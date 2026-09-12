using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorClientPinCommand(
    uint pinUvAuthProtocol,
    AuthenticatorClientPinSubCommand subCommand,
    CredentialPublicKey? keyAgreement = null,
    byte[]? pinUvAuthParam = null,
    byte[]? newPinEnc = null,
    byte[]? pinHashEnc = null,
    PinUvAuthTokenPermissions? permissions = null,
    string? rpId = null) : CtapCommand
{
    /// <summary>
    /// Required PIN protocol version chosen by the client.
    /// </summary>
    [CborMember(0x01)]
    public uint PinUvAuthProtocol { get; } = pinUvAuthProtocol;

    /// <summary>
    /// The authenticator Client PIN sub command currently being requested.
    /// </summary>
    [CborMember(0x02)]
    public AuthenticatorClientPinSubCommand SubCommand { get; } = subCommand;

    /// <summary>
    /// Public key of platformKeyAgreementKey.
    /// The COSE_Key-encoded public key MUST contain the optional "alg" parameter and MUST NOT contain any other optional parameters.
    /// The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
    /// </summary>
    [CborMember(0x03)]
    public CredentialPublicKey? KeyAgreement { get; } = keyAgreement;

    /// <summary>
    /// First 16 bytes of HMAC-SHA-256 of encrypted contents using sharedSecret.
    /// </summary>
    [CborMember(0x04)]
    public byte[]? PinUvAuthParam { get; } = pinUvAuthParam;

    /// <summary>
    /// Encrypted new PIN using sharedSecret.
    /// </summary>
    [CborMember(0x05)]
    public byte[]? NewPinEnc { get; } = newPinEnc;

    /// <summary>
    /// Encrypted first 16 bytes of SHA-256 of PIN using sharedSecret.
    /// </summary>
    [CborMember(0x06)]
    public byte[]? PinHashEnc { get; } = pinHashEnc;

    /// <summary>
    /// The permissions to associate with the returned pinUvAuthToken. Mandatory for
    /// <see cref="AuthenticatorClientPinSubCommand.GetPinUvAuthTokenUsingPinWithPermissions"/> and
    /// <see cref="AuthenticatorClientPinSubCommand.GetPinUvAuthTokenUsingUvWithPermissions"/>.
    /// <para>New in CTAP 2.1.</para>
    /// </summary>
    [CborMember(0x09)]
    public PinUvAuthTokenPermissions? Permissions { get; } = permissions;

    /// <summary>
    /// The RP ID to assign as the permissions RP ID. Required for some permissions
    /// (<see cref="PinUvAuthTokenPermissions.MakeCredential"/>, <see cref="PinUvAuthTokenPermissions.GetAssertion"/>),
    /// optional for others.
    /// <para>New in CTAP 2.1.</para>
    /// </summary>
    [CborMember(0x0A)]
    public string? RpId { get; } = rpId;

    public override CtapCommandType Type => CtapCommandType.AuthenticatorClientPin;

    protected override CborObject? GetParameters()
    {
        var cbor = new CborMap
        {
            { 0x01, PinUvAuthProtocol },
            { 0x02, (int)SubCommand }
        };

        if (KeyAgreement != null)
        {
            cbor.Add(0x03, KeyAgreement.GetCborObject());
        }

        if (PinUvAuthParam != null)
        {
            cbor.Add(0x04, PinUvAuthParam);
        }

        if (NewPinEnc != null)
        {
            cbor.Add(0x05, NewPinEnc);
        }

        if (PinHashEnc != null)
        {
            cbor.Add(0x06, PinHashEnc);
        }

        if (Permissions.HasValue)
        {
            cbor.Add(0x09, (int)Permissions.Value);
        }

        if (RpId != null)
        {
            cbor.Add(0x0A, RpId);
        }

        return cbor;
    }
}

public enum AuthenticatorClientPinSubCommand
{
    #pragma warning disable format
    GetPinRetries                              = 0x01,
    GetKeyAgreement                         = 0x02,
    SetPin                                  = 0x03,
    ChangePin                               = 0x04,

    /// <summary>Superseded by <see cref="GetPinUvAuthTokenUsingUvWithPermissions"/> or <see cref="GetPinUvAuthTokenUsingPinWithPermissions"/>; kept for backwards compatibility.</summary>
    GetPinToken                             = 0x05,

    /// <summary>New in CTAP 2.1.</summary>
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,

    /// <summary>New in CTAP 2.1.</summary>
    GetUVRetries                            = 0x07,

    /// <summary>New in CTAP 2.1.</summary>
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
    #pragma warning restore format
}

/// <summary>
/// Bitfield of permissions a pinUvAuthToken may be granted, per §6.5.5.7 of the CTAP 2.3 Proposed Standard.
/// </summary>
[Flags]
public enum PinUvAuthTokenPermissions
{
    /// <summary>Allows use with authenticatorMakeCredential. Requires the RP ID parameter.</summary>
    MakeCredential = 0x01,

    /// <summary>Allows use with authenticatorGetAssertion. Requires the RP ID parameter.</summary>
    GetAssertion = 0x02,

    /// <summary>Allows use with authenticatorCredentialManagement. RP ID optional, scoping the token to that RP's credentials if present.</summary>
    CredentialManagement = 0x04,

    /// <summary>Allows use with authenticatorBioEnrollment. The RP ID parameter is ignored.</summary>
    BioEnrollment = 0x08,

    /// <summary>Allows use with authenticatorLargeBlobs (writes). The RP ID parameter is ignored.</summary>
    LargeBlobWrite = 0x10,

    /// <summary>Allows use with authenticatorConfig. The RP ID parameter is ignored.</summary>
    AuthenticatorConfiguration = 0x20,

    /// <summary>
    /// Grants the persistentPinUvAuthToken read-only access to authenticatorCredentialManagement.
    /// Mutually exclusive with every other permission in the same request.
    /// </summary>
    PersistentCredentialManagementReadOnly = 0x40,
}
