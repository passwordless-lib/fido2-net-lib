using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// This client registration extension facilitates reporting certain credential properties known by the client to the requesting WebAuthn Relying Party upon creation of a public key credential source as a result of a registration ceremony.
/// </summary>
public class CredentialPropertiesOutput
{
    /// <summary>
    /// This OPTIONAL property, known abstractly as the resident key credential property (i.e., client-side
    /// discoverable credential property), indicates whether the credential returned by a registration ceremony
    /// is a client-side discoverable credential.
    /// </summary>
    /// <remarks>
    /// Three-state, per WebAuthn L3 §10.1.3: <see langword="true"/> means the credential is discoverable,
    /// <see langword="false"/> means it is a server-side credential, and <see langword="null"/> means the client
    /// did not report which -- "If rk is not present, it is not known whether the credential is a discoverable
    /// credential or a server-side credential." Treating an absent value as <see langword="false"/> would claim
    /// knowledge the client did not provide.
    /// </remarks>
    [JsonPropertyName("rk")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Rk { get; init; }
}
