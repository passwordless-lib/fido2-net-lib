#nullable enable
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// This client registration extension facilitates reporting certain credential properties known by the client to the requesting WebAuthn Relying Party upon creation of a public key credential source as a result of a registration ceremony.
/// </summary>
public class CredentialPropertiesOutput
{
    /// <summary>
    /// This OPTIONAL property, known abstractly as the resident key credential property (i.e., client-side discoverable credential property), is a Boolean value indicating whether the PublicKeyCredential returned as a result of a registration ceremony is a client-side discoverable credential. If rk is true, the credential is a discoverable credential. if rk is false, the credential is a server-side credential. If rk is not present, it is not known whether the credential is a discoverable credential or a server-side credential.
    /// </summary>
    [JsonPropertyName("rk")]
    public bool Rk { get; set; }


    /// <summary>
    /// This OPTIONAL property is a human-palatable description of the credential’s managing authenticator, chosen by the user.
    /// </summary>
    [JsonPropertyName("authenticatorDisplayName")]
    public string? AuthenticatorDisplayName { get; set; }
}
