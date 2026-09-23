using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// An entry in an authenticatorBioEnrollment enumerateEnrollments response's <c>templateInfos</c> array.
/// </summary>
public sealed class BioEnrollmentTemplateInfo
{
    /// <summary>
    /// Template Identifier.
    /// </summary>
    public required byte[] TemplateId { get; init; }

    /// <summary>
    /// Template Friendly Name.
    /// </summary>
    public string? TemplateFriendlyName { get; init; }

    internal static BioEnrollmentTemplateInfo FromCborObject(CborObject cbor)
    {
        byte[]? templateId = null;
        string? templateFriendlyName = null;

        foreach (var (key, value) in (CborMap)cbor)
        {
            switch ((int)key)
            {
                case 0x01:
                    templateId = (byte[])value;
                    break;
                case 0x02:
                    templateFriendlyName = (string)value;
                    break;
            }
        }

        return new BioEnrollmentTemplateInfo { TemplateId = templateId!, TemplateFriendlyName = templateFriendlyName };
    }
}

/// <summary>
/// Response to the authenticatorBioEnrollment (0x09) command. Which members are populated
/// depends on the sub command that produced this response.
/// </summary>
public sealed class AuthenticatorBioEnrollmentResponse
{
    /// <summary>
    /// The user verification modality. For fingerprint, its value is <see cref="AuthenticatorBioEnrollmentModality.Fingerprint"/>.
    /// </summary>
    [CborMember(0x01)]
    public AuthenticatorBioEnrollmentModality? Modality { get; set; }

    /// <summary>
    /// The type of fingerprint sensor: 1 for touch type, 2 for swipe type.
    /// </summary>
    [CborMember(0x02)]
    public int? FingerprintKind { get; set; }

    /// <summary>
    /// The maximum good samples required for enrollment.
    /// </summary>
    [CborMember(0x03)]
    public int? MaxCaptureSamplesRequiredForEnroll { get; set; }

    /// <summary>
    /// Template Identifier of a new or in-progress enrollment.
    /// </summary>
    [CborMember(0x04)]
    public byte[]? TemplateId { get; set; }

    /// <summary>
    /// Status of enrollment of the last sample. See CTAP2_ENROLL_FEEDBACK_* values in §6.7.
    /// </summary>
    [CborMember(0x05)]
    public int? LastEnrollSampleStatus { get; set; }

    /// <summary>
    /// Number of samples still required to complete the enrollment.
    /// </summary>
    [CborMember(0x06)]
    public int? RemainingSamples { get; set; }

    /// <summary>
    /// Enrollments available on the authenticator, populated by enumerateEnrollments.
    /// </summary>
    [CborMember(0x07)]
    public BioEnrollmentTemplateInfo[]? TemplateInfos { get; set; }

    /// <summary>
    /// The maximum number of bytes the authenticator will accept as a templateFriendlyName.
    /// </summary>
    [CborMember(0x08)]
    public int? MaxTemplateFriendlyName { get; set; }

    public static AuthenticatorBioEnrollmentResponse FromCborObject(CborObject cbor)
    {
        var result = new AuthenticatorBioEnrollmentResponse();

        foreach (var (key, value) in (CborMap)cbor)
        {
            switch ((int)key)
            {
                #pragma warning disable format
                case 0x01: result.Modality                            = (AuthenticatorBioEnrollmentModality)(int)value; break;
                case 0x02: result.FingerprintKind                     = (int?)value;                                    break;
                case 0x03: result.MaxCaptureSamplesRequiredForEnroll  = (int?)value;                                    break;
                case 0x04: result.TemplateId                          = (byte[])value;                                  break;
                case 0x05: result.LastEnrollSampleStatus              = (int?)value;                                    break;
                case 0x06: result.RemainingSamples                    = (int?)value;                                    break;
                case 0x07: result.TemplateInfos                       = DecodeTemplateInfos((CborArray)value);          break;
                case 0x08: result.MaxTemplateFriendlyName             = (int?)value;                                    break;
                #pragma warning restore format
            }
        }

        return result;
    }

    private static BioEnrollmentTemplateInfo[] DecodeTemplateInfos(CborArray array)
    {
        var result = new BioEnrollmentTemplateInfo[array.Length];

        for (int i = 0; i < array.Length; i++)
        {
            result[i] = BioEnrollmentTemplateInfo.FromCborObject(array[i]);
        }

        return result;
    }
}
