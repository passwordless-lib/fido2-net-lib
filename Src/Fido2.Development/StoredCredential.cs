#nullable disable

using Fido2NetLib.Objects;

namespace Fido2NetLib.Development;

public class StoredCredential
{
    /// <summary>
    /// The Credential ID of the public key credential source.
    /// </summary>
    public required byte[] Id { get; set; }

    /// <summary>
    /// The credential public key of the public key credential source.
    /// </summary>
    public byte[] PublicKey { get; set; }

    /// <summary>
    /// The latest value of the signature counter in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public uint SignCount { get; set; }

    /// <summary>
    /// The value returned from getTransports() when the public key credential source was registered.
    /// </summary>
    public AuthenticatorTransport[] Transports { get; set; }

    /// <summary>
    /// The attachment modality the client reported at registration, if any. Informational only.
    /// See <see cref="RegisteredPublicKeyCredential.AuthenticatorAttachment"/>.
    /// </summary>
    public AuthenticatorAttachment? AuthenticatorAttachment { get; set; }

    /// <summary>
    /// Indicates whether any credential from this public key credential source has had the UV flag set.
    /// See <see cref="RegisteredPublicKeyCredential.UvInitialized"/>.
    /// </summary>
    public bool UvInitialized { get; set; }

    /// <summary>
    /// The value of the BE flag when the public key credential source was created.
    /// </summary>
    public bool IsBackupEligible { get; set; }

    /// <summary>
    /// The latest value of the BS flag in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public bool IsBackedUp { get; set; }

    /// <summary>
    /// The value of the attestationObject attribute when the public key credential source was registered.
    /// Storing this enables the Relying Party to reference the credential's attestation statement at a later time.
    /// </summary>
    public byte[] AttestationObject { get; set; }

    /// <summary>
    /// The value of the clientDataJSON attribute when the public key credential source was registered.
    /// Storing this in combination with the above attestationObject item enables the Relying Party to re-verify the attestation signature at a later time.
    /// </summary>
    public byte[] AttestationClientDataJson { get; set; }

    /// <summary>
    /// What the client reported through the <c>credProps</c> extension's <c>rk</c> value at registration:
    /// <see langword="true"/> for a discoverable credential, <see langword="false"/> for a server-side
    /// credential, and <see langword="null"/> when the client did not say which.
    /// See <see cref="CredentialPropertiesOutput.Rk"/>.
    /// </summary>
    public bool? IsDiscoverable { get; set; }

    public byte[] UserId { get; set; }

    /// <summary>
    /// Exposes an Descriptor Object for this credential, used as input to the library for certain operations.
    /// </summary>
    public PublicKeyCredentialDescriptor Descriptor => new(PublicKeyCredentialType.PublicKey, Id, Transports);

    public byte[] UserHandle { get; set; }

    public string AttestationFormat { get; set; }

    public DateTimeOffset RegDate { get; set; }

    public Guid AaGuid { get; set; }
}
