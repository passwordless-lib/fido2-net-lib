using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

public sealed class AuthenticatorMakeCredentialCommand : CtapCommand
{
    public AuthenticatorMakeCredentialCommand(
        byte[] clientDataHash,
        PublicKeyCredentialRpEntity rpEntity,
        PublicKeyCredentialUserEntity user,
        PubKeyCredParam[] pubKeyCredParams,
        AuthenticatorMakeCredentialOptions options,
        byte[]? pinAuth = null,
        uint? pinProtocol = null)
    {
        ClientDataHash = clientDataHash;
        Rp = rpEntity;
        User = user;
        PubKeyCredParams = pubKeyCredParams;
        Options = options;
        PinAuth = pinAuth;
        PinProtocol = pinProtocol;
    }

    /// <summary>
    /// Hash of the ClientData contextual binding specified by host.
    /// </summary>
    [CborMember(0x01)]
    public byte[] ClientDataHash { get; }

    /// <summary>
    /// This PublicKeyCredentialRpEntity data structure describes a Relying Party with which the new public key credential will be associated. 
    /// It contains the Relying party identifier of type text string, (optionally) a human-friendly RP name of type text string, and (optionally) a URL of type text string, referencing a RP icon image. 
    /// </summary>
    [CborMember(0x02)]
    public PublicKeyCredentialRpEntity Rp { get; }

    [CborMember(0x03)]
    public PublicKeyCredentialUserEntity User { get; }

    /// <summary>
    /// This sequence is ordered from most preferred (by the RP) to least preferred.
    /// </summary>
    [CborMember(0x04)]
    public PubKeyCredParam[] PubKeyCredParams { get; }

    /// <summary>
    /// The authenticator returns an error if the authenticator already contains one of the credentials enumerated in this sequence. 
    /// This allows RPs to limit the creation of multiple credentials for the same account on a single authenticator.
    /// </summary>
    [CborMember(0x05)]
    public PublicKeyCredentialDescriptor[]? ExcludeList { get; }

    [CborMember(0x06)]
    public CborMap? Extensions { get; }

    [CborMember(0x07)]
    public AuthenticatorMakeCredentialOptions? Options { get; }

    /// <summary>
    /// First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken which platform got from the authenticator:
    /// HMAC-SHA-256(pinToken, clientDataHash).
    /// </summary>
    [CborMember(0x08)]
    public byte[]? PinAuth { get; }

    /// <summary>
    /// PIN protocol version chosen by the client
    /// </summary>
    [CborMember(0x09)]
    public uint? PinProtocol { get; }

    public override CtapCommandType Type => CtapCommandType.AuthenticatorMakeCredential;

    protected override CborObject? GetParameters()
    {
        var cbor = new CborMap
        {
            { 0x01, ClientDataHash },
            { 0x02, Rp.ToCborObject() },
            { 0x03, User.ToCborObject() }
        };

        var pubKeyCredParams = new CborArray();

        foreach (PubKeyCredParam pubKeyCredParam in PubKeyCredParams)
        {
            pubKeyCredParams.Add(pubKeyCredParam.ToCborObject());
        };

        cbor.Add(0x04, pubKeyCredParams);

        if (ExcludeList is { Length: > 0 })
        {
            cbor.Add(0x05, ExcludeList.ToCborArray()); // excludeList
        }

        // | { "hmac-secret": true }
        if (Extensions != null)
        {
            cbor.Add(0x06, Extensions);
        }

        if (Options is AuthenticatorMakeCredentialOptions options)
        {
            // 0x07 : options     
            cbor.Add(0x07, options.ToCborObject());
        }

        if (PinAuth is not null)
        {
            cbor.Add(0x08, PinAuth);           // pinAuth(0x08)
            cbor.Add(0x09, PinProtocol ?? 1);  // pinProtocol(0x09)
        }

        return cbor;
    }
}

public sealed class AuthenticatorMakeCredentialOptions
{
    /// <summary>
    /// Instructs the authenticator to store the key material on the device.
    /// </summary>
    [CborMember("rk")]
    public bool? ResidentKey { get; init; }

    /// <summary>
    /// Instructs the authenticator to require a gesture that verifies the user to complete the request.
    /// Examples of such gestures are fingerprint scan or a PIN.
    /// </summary>
    [CborMember("uv")]
    public bool? UserVerification { get; init; }


    public CborMap ToCborObject()
    {
        var result = new CborMap();

        if (ResidentKey is bool rk)
        {
            result.Add("rk", rk);
        }

        if (UserVerification is bool uv)
        {
            result.Add("uv", uv);
        }

        return result;
    }
}

