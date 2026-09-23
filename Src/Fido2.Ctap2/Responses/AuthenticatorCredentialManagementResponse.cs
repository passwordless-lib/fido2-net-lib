using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Response to the authenticatorCredentialManagement (0x0A) command. Which members are
/// populated depends on the sub command that produced this response.
/// </summary>
public sealed class AuthenticatorCredentialManagementResponse
{
    /// <summary>
    /// Number of existing discoverable credentials present on the authenticator.
    /// Populated by <see cref="AuthenticatorCredentialManagementSubCommand.GetCredsMetadata"/>.
    /// </summary>
    [CborMember(0x01)]
    public int? ExistingResidentCredentialsCount { get; set; }

    /// <summary>
    /// Number of maximum possible remaining discoverable credentials which can be created on the authenticator.
    /// Populated by <see cref="AuthenticatorCredentialManagementSubCommand.GetCredsMetadata"/>.
    /// </summary>
    [CborMember(0x02)]
    public int? MaxPossibleRemainingResidentCredentialsCount { get; set; }

    /// <summary>
    /// RP Information. Populated by <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateRPsBegin"/>
    /// and <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateRPsGetNextRP"/>.
    /// </summary>
    [CborMember(0x03)]
    public PublicKeyCredentialRpEntity? Rp { get; set; }

    /// <summary>
    /// RP ID SHA-256 hash. Populated by <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateRPsBegin"/>
    /// and <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateRPsGetNextRP"/>.
    /// </summary>
    [CborMember(0x04)]
    public byte[]? RpIdHash { get; set; }

    /// <summary>
    /// Total number of RPs present on the authenticator.
    /// Populated by <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateRPsBegin"/>.
    /// </summary>
    [CborMember(0x05)]
    public int? TotalRPs { get; set; }

    /// <summary>
    /// User Information. Populated by <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsBegin"/>
    /// and <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsGetNextCredential"/>.
    /// </summary>
    [CborMember(0x06)]
    public PublicKeyCredentialUserEntity? User { get; set; }

    /// <summary>
    /// The credential identifier. Populated by <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsBegin"/>
    /// and <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsGetNextCredential"/>.
    /// </summary>
    [CborMember(0x07)]
    public PublicKeyCredentialDescriptor? CredentialId { get; set; }

    /// <summary>
    /// The public key of the credential, in COSE_Key format. Populated by
    /// <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsBegin"/> and
    /// <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsGetNextCredential"/>.
    /// </summary>
    [CborMember(0x08)]
    public CredentialPublicKey? PublicKey { get; set; }

    /// <summary>
    /// Total number of credentials for this RP.
    /// Populated by <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsBegin"/>.
    /// </summary>
    [CborMember(0x09)]
    public int? TotalCredentials { get; set; }

    /// <summary>
    /// Credential protection policy. Populated by <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsBegin"/>
    /// and <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsGetNextCredential"/>.
    /// </summary>
    [CborMember(0x0A)]
    public int? CredProtect { get; set; }

    /// <summary>
    /// The contents, if any, of the stored largeBlobKey. Populated by
    /// <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsBegin"/> and
    /// <see cref="AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsGetNextCredential"/>.
    /// </summary>
    [CborMember(0x0B)]
    public byte[]? LargeBlobKey { get; set; }

    /// <summary>
    /// Present only if the authenticator supports the thirdPartyPayment extension; <c>true</c> if
    /// the credential is third-party payment enabled.
    /// <para>New in CTAP 2.3.</para>
    /// </summary>
    [CborMember(0x0C)]
    public bool? ThirdPartyPayment { get; set; }

    /// <summary>
    /// Parses a CBOR object into an <see cref="AuthenticatorCredentialManagementResponse"/>.
    /// </summary>
    public static AuthenticatorCredentialManagementResponse FromCborObject(CborObject cbor)
    {
        var result = new AuthenticatorCredentialManagementResponse();

        foreach (var (key, value) in (CborMap)cbor)
        {
            switch ((int)key)
            {
                #pragma warning disable format
                case 0x01: result.ExistingResidentCredentialsCount              = (int?)value;                                     break;
                case 0x02: result.MaxPossibleRemainingResidentCredentialsCount  = (int?)value;                                     break;
                case 0x03: result.Rp                                           = CborHelper.DecodePublicKeyCredentialRpEntity((CborMap)value);   break;
                case 0x04: result.RpIdHash                                     = (byte[])value;                                    break;
                case 0x05: result.TotalRPs                                     = (int?)value;                                     break;
                case 0x06: result.User                                        = CborHelper.DecodePublicKeyCredentialUserEntity((CborMap)value); break;
                case 0x07: result.CredentialId                                 = CborHelper.DecodePublicKeyCredentialDescriptor((CborMap)value); break;
                case 0x08: result.PublicKey                                    = new CredentialPublicKey((CborMap)value);           break;
                case 0x09: result.TotalCredentials                             = (int?)value;                                     break;
                case 0x0A: result.CredProtect                                  = (int?)value;                                     break;
                case 0x0B: result.LargeBlobKey                                 = (byte[])value;                                    break;
                case 0x0C: result.ThirdPartyPayment                            = (bool?)value;                                     break;
                #pragma warning restore format
            }
        }

        return result;
    }
}
