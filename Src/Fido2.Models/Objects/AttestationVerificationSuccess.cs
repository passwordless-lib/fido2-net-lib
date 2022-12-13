using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// Holds parsed credential data
/// </summary>
public class AttestationVerificationSuccess : AssertionVerificationResult
{
    public Fido2User User { get; set; }
    public string CredType { get; set; }
    public System.Guid Aaguid { get; set; }
    /// <summary>
    /// The type of the public key credential source.
    /// </summary>
    public PublicKeyCredentialType Type { get; set; } = PublicKeyCredentialType.PublicKey;
    /// <summary>
    /// The Credential ID of the public key credential source.
    /// </summary>
    public byte[] Id { get; set; }
    /// <summary>
    /// The credential public key of the public key credential source.
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] PublicKey { get; set; }
    /// <summary>
    /// The value returned from getTransports() when the public key credential source was registered.
    /// </summary>
    public AuthenticatorTransport[] Transports { get; set; }
    /// <summary>
    /// The value of the BE flag when the public key credential source was created.
    /// </summary>
    public bool BE { get; set; }
    /// <summary>
    /// The value of the attestationObject attribute when the public key credential source was registered. 
    /// Storing this enables the Relying Party to reference the credential's attestation statement at a later time.
    /// </summary>
    public byte[] AttestationObject { get; set; }
    /// <summary>
    /// The value of the clientDataJSON attribute when the public key credential source was registered. 
    /// Storing this in combination with the above attestationObject item enables the Relying Party to re-verify the attestation signature at a later time.
    /// </summary>
    public byte[] AttestationClientDataJSON { get; set; }
}
