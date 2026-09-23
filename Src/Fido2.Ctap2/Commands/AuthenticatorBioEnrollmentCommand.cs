using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Request for the authenticatorBioEnrollment (0x09) command, used to provision, enumerate, and
/// delete biometric (e.g. fingerprint) enrollments on the authenticator.
/// <para>New in CTAP 2.1 (see §6.7 of the CTAP 2.3 Proposed Standard).</para>
/// </summary>
public sealed class AuthenticatorBioEnrollmentCommand(
    AuthenticatorBioEnrollmentModality? modality = null,
    AuthenticatorBioEnrollmentSubCommand? subCommand = null,
    CborMap? subCommandParams = null,
    uint? pinUvAuthProtocol = null,
    byte[]? pinUvAuthParam = null,
    bool? getModality = null) : CtapCommand
{
    /// <summary>
    /// The user verification modality being requested.
    /// </summary>
    [CborMember(0x01)]
    public AuthenticatorBioEnrollmentModality? Modality { get; } = modality;

    /// <summary>
    /// The authenticator user verification sub command currently being requested.
    /// </summary>
    [CborMember(0x02)]
    public AuthenticatorBioEnrollmentSubCommand? SubCommand { get; } = subCommand;

    /// <summary>
    /// Sub command specific parameters, if any.
    /// </summary>
    [CborMember(0x03)]
    public CborMap? SubCommandParams { get; } = subCommandParams;

    /// <summary>
    /// PIN/UV protocol version chosen by the platform.
    /// </summary>
    [CborMember(0x04)]
    public uint? PinUvAuthProtocol { get; } = pinUvAuthProtocol;

    /// <summary>
    /// <c>authenticate(pinUvAuthToken, modality || subCommand || subCommandParams)</c>, where
    /// <c>subCommandParams</c> is only included, CBOR-encoded, when present.
    /// </summary>
    [CborMember(0x05)]
    public byte[]? PinUvAuthParam { get; } = pinUvAuthParam;

    /// <summary>
    /// Requests the user verification type modality. MUST be set to <c>true</c> when present.
    /// </summary>
    [CborMember(0x06)]
    public bool? GetModality { get; } = getModality;

    public override CtapCommandType Type => CtapCommandType.AuthenticatorBioEnrollment;

    protected override CborObject? GetParameters()
    {
        var cbor = new CborMap();

        if (Modality.HasValue)
        {
            cbor.Add(0x01, (int)Modality.Value);
        }

        if (SubCommand.HasValue)
        {
            cbor.Add(0x02, (int)SubCommand.Value);
        }

        if (SubCommandParams != null)
        {
            cbor.Add(0x03, SubCommandParams);
        }

        if (PinUvAuthProtocol.HasValue)
        {
            cbor.Add(0x04, (int)PinUvAuthProtocol.Value);
        }

        if (PinUvAuthParam != null)
        {
            cbor.Add(0x05, PinUvAuthParam);
        }

        if (GetModality.HasValue)
        {
            cbor.Add(0x06, (CborObject)(CborBoolean)GetModality.Value);
        }

        return cbor;
    }
}

public enum AuthenticatorBioEnrollmentModality
{
    Fingerprint = 0x01,
}

public enum AuthenticatorBioEnrollmentSubCommand
{
    #pragma warning disable format
    EnrollBegin              = 0x01,
    EnrollCaptureNextSample  = 0x02,
    CancelCurrentEnrollment  = 0x03,
    EnumerateEnrollments     = 0x04,
    SetFriendlyName          = 0x05,
    RemoveEnrollment         = 0x06,
    GetFingerprintSensorInfo = 0x07,
    #pragma warning restore format
}
