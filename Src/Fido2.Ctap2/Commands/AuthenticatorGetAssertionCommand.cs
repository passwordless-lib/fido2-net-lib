using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorGetAssertionCommand : CtapCommand
{
    public AuthenticatorGetAssertionCommand(
        string rpId,
        byte[] clientDataHash,
        PublicKeyCredentialDescriptor[] allowList,
        CborMap? extensions = null,
        AuthenticatorGetAssertionOptions? options = null,
        byte[]? pinAuth = null,
        uint? pinProtocol = null)
    {
        ArgumentNullException.ThrowIfNull(rpId);
        ArgumentNullException.ThrowIfNull(clientDataHash);

        RpId = rpId;
        ClientDataHash = clientDataHash;
        AllowList = allowList;
        Extensions = extensions;
        Options = options;
        PinAuth = pinAuth;
        PinProtocol = pinProtocol;
    }

    /// <summary>
    /// Relying party identifier.
    /// </summary>
    [CborMember(0x01)]
    public string RpId { get; }

    /// <summary>
    /// Hash of the serialized client data collected by the host.
    /// </summary>
    [CborMember(0x02)]
    public byte[] ClientDataHash { get; }

    /// <summary>
    /// A sequence of PublicKeyCredentialDescriptor structures, each denoting a credential, as specified in [WebAuthn].
    /// If this parameter is present and has 1 or more entries, the authenticator MUST only generate an assertion using one of the denoted credentials.
    /// </summary>
    [CborMember(0x03)]
    public PublicKeyCredentialDescriptor[] AllowList { get; }

    /// <summary>
    /// CBOR map of extension identifier → authenticator extension input values.
    /// </summary>
    [CborMember(0x04)]
    public CborMap? Extensions { get; }

    /// <summary>
    /// Map of authenticator options.
    /// </summary>
    [CborMember(0x05)]
    public AuthenticatorGetAssertionOptions? Options { get; }

    /// <summary>
    /// First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken which platform got from the authenticator:
    /// HMAC-SHA-256(pinToken, clientDataHash).
    /// </summary>
    [CborMember(0x06)]
    public byte[]? PinAuth { get; }

    /// <summary>
    /// PIN protocol version selected by client.
    /// </summary>
    [CborMember(0x07)]
    public uint? PinProtocol { get; }

    public override CtapCommandType Type => CtapCommandType.AuthenticatorGetAssertion;

    protected override CborObject? GetParameters()
    {
        var cbor = new CborMap
        {
            { 0x01, RpId },
            { 0x02, ClientDataHash },
            { 0x03, AllowList.ToCborArray() } // allowList
        };

        if (Extensions != null)
        {
            cbor.Add(0x04, Extensions);
        }

        if (Options != null)
        {
            cbor.Add(0x05, Options.ToCborObject());
        }

        if (PinAuth is not null)
        {
            cbor.Add(0x06, PinAuth);           // pinAuth(0x08)
            cbor.Add(0x07, PinProtocol ?? 1);  // pinProtocol(0x09)
        }

        return cbor;
    }
}

public sealed class AuthenticatorGetAssertionOptions
{
    /// <summary>
    /// Instructs the authenticator to require user consent to complete the operation.
    /// </summary>
    [CborMember("up")]
    public bool? UserPresence { get; init; }

    /// <summary>
    /// Instructs the authenticator to require a gesture that verifies the user to complete the request. Examples of such gestures are fingerprint scan or a PIN.
    /// </summary>
    [CborMember("uv")]
    public bool? UserVerification { get; init; }

    public CborMap ToCborObject()
    {
        var result = new CborMap();

        if (UserPresence is bool up)
        {
            result.Add("up", up);
        }

        if (UserVerification is bool uv)
        {
            result.Add("uv", uv);
        }

        return result;
    }
}
