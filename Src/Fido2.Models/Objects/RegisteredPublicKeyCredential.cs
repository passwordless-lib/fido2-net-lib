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
    /// The value of the <c>rp.id</c> parameter specified in the <c>create()</c> operation during credential
    /// registration. This is a core property of the credential that determines where it can be used. Storing it
    /// helps later on: to audit the credential's use, to troubleshoot authentication problems, or to use it
    /// across different domains via
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">Related Origins</see>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#credential-record"/>
    /// </remarks>
    public string RpId { get; init; }

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
    /// The authenticator extension outputs from the extensions block of the authenticator data, decoded into
    /// the outputs CTAP defines. Never <see langword="null"/>; its members are <see langword="null"/> when the
    /// authenticator returned no such output.
    /// </summary>
    public AuthenticationExtensionsAuthenticatorOutputs AuthenticatorExtensionResults { get; init; } = new();

    /// <summary>
    /// The value of the id-fido-gen-ce-sernum extension (OID 1.3.6.1.4.1.45724.1.1.2) in the attestation
    /// certificate, or <see langword="null"/> when the certificate did not carry one. This uniquely identifies a
    /// single device against a particular AAGUID and remains constant across factory resets, so it is only ever
    /// populated for a ceremony that requested
    /// <see cref="AttestationConveyancePreference.Enterprise"/> attestation.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-enterprise-packed-attestation-cert-requirements"/>
    /// </remarks>
    public byte[] EnterpriseAttestationSerialNumber { get; init; }

    /// <summary>
    /// The value of the id-fido-gen-ce-fw-version extension (OID 1.3.6.1.4.1.45724.1.1.5) in the attestation
    /// certificate, or <see langword="null"/> when the certificate did not carry one. It differentiates the
    /// firmware of one authenticator model and is incremented for each new firmware release.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="EnterpriseAttestationSerialNumber"/> this identifies a build rather than a device, so
    /// it carries no tracking risk and is populated for any conveyance preference. It is directly comparable
    /// with the <c>authenticatorVersion</c> of the model's Metadata Service status report, which is how a
    /// Relying Party can tell that an authenticator predates a certification or a firmware fix.
    /// <para>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements"/>
    /// </para>
    /// </remarks>
    public ulong? FirmwareVersion { get; init; }

    /// <summary>
    /// The attestation type the attestation statement's verification procedure established: "none", "self",
    /// "basic", "attca" or "anonca" (WebAuthn Level 3, 6.5.3 Attestation Types). Registration succeeds for every
    /// type, so a Relying Party that only wants to trust certain kinds of attestation, for instance not "self",
    /// which asserts nothing about the authenticator that created the credential, and not "none", decides here.
    /// </summary>
    public string AttestationType { get; init; }

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

    /// <summary>
    /// For a credential created for Secure Payment Confirmation, the browser-bound key's public key as a COSE_Key, when
    /// the browser supplied one and its signature over the client data verified; otherwise <see langword="null"/>.
    /// Store it to compare against the key later transactions are confirmed with.
    /// </summary>
#nullable enable
    public byte[]? BrowserBoundPublicKey { get; init; }
#nullable restore
}
