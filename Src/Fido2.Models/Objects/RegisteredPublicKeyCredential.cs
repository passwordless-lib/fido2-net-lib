using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// Holds parsed credential data
/// </summary>
public class RegisteredPublicKeyCredential : Fido2ResponseBase
{
    /// <summary>
    /// The type of the public key credential source.
    /// </summary>
    public PublicKeyCredentialType Type { get; init; } = PublicKeyCredentialType.PublicKey;

    /// <summary>
    /// The Credential ID of the public key credential source.
    /// </summary>
    public byte[] Id { get; init; }

    /// <summary>
    /// The credential public key of the public key credential source.
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] PublicKey { get; init; }

    /// <summary>
    /// The value returned from getTransports() when the public key credential source was registered.
    /// </summary>
    public AuthenticatorTransport[] Transports { get; init; }

    /// <summary>
    /// The latest value of the signature counter in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public uint SignCount { get; init; }

    /// <summary>
    /// The value of the BE flag when the public key credential source was created.
    /// </summary>
    public bool IsBackupEligible { get; init; }

    /// <summary>
    /// The latest value of the BS flag in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public bool IsBackedUp { get; init; }

    /// <summary>
    /// The public key portion of a hardware-bound device key pair
    /// </summary>
    public byte[] DevicePublicKey { get; init; }

    public Guid AaGuid { get; init; }

    public Fido2User User { get; init; }

    public string AttestationFormat { get; init; }

    /// <summary>
    /// The value of the attestationObject attribute when the public key credential source was registered. 
    /// Storing this enables the Relying Party to reference the credential's attestation statement at a later time.
    /// </summary>
    public byte[] AttestationObject { get; init; }

    /// <summary>
    /// The value of the clientDataJSON attribute when the public key credential source was registered. 
    /// Storing this in combination with the above attestationObject item enables the Relying Party to re-verify the attestation signature at a later time.
    /// </summary>
    public byte[] AttestationClientDataJson { get; init; }
}
