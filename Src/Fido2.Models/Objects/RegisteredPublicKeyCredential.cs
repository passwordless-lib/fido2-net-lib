#nullable disable

using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// Holds parsed credential data
/// </summary>
public class RegisteredPublicKeyCredential
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
    /// The attachment modality the client reported for the authenticator that created this credential, or
    /// <see langword="null"/> if it reported none or one this library does not recognize. Informational only:
    /// it is not part of the signed authenticator data.
    /// </summary>
    public AuthenticatorAttachment? AuthenticatorAttachment { get; init; }

    /// <summary>
    /// Indicates whether any credential from this public key credential source has had the UV flag set.
    /// When <see langword="true"/>, the Relying Party MAY consider the UV flag as an authentication factor in
    /// authentication ceremonies. When <see langword="false"/> -- including an authentication ceremony where it
    /// would be updated to <see langword="true"/> -- the UV flag MUST NOT be relied upon as an authentication
    /// factor, because no trust relationship with the authenticator's user verification has been established yet.
    /// Updating this from <see langword="false"/> to <see langword="true"/> SHOULD require authorization by an
    /// additional authentication factor equivalent to WebAuthn user verification.
    /// <see href="https://www.w3.org/TR/webauthn-3/#credential-record"/>
    /// </summary>
    public bool UvInitialized { get; init; }

    /// <summary>
    /// The value of the BE flag when the public key credential source was created.
    /// </summary>
    public bool IsBackupEligible { get; init; }

    /// <summary>
    /// The latest value of the BS flag in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public bool IsBackedUp { get; init; }

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
