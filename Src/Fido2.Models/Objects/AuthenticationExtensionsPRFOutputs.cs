#nullable disable

using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// This is a dictionary containing the PRF extension output values
/// </summary>
public sealed class AuthenticationExtensionsPRFOutputs
{
    /// <summary>
    /// Whether PRFs are available for use with the created credential, or <see langword="null"/> when the
    /// client did not report it.
    /// </summary>
    /// <remarks>
    /// Reported on registration ceremonies and on no authentication ceremony: client extension processing
    /// for an assertion initializes the output to an empty dictionary and only ever sets
    /// <see cref="Results"/>. A <see langword="null"/> here therefore means "not reported", which is a
    /// different thing from a reported <see langword="false"/>.
    /// <para>
    /// <see href="https://www.w3.org/TR/webauthn-3/#prf-extension"/>
    /// </para>
    /// </remarks>
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Enabled { get; init; }

    /// <summary>
    /// The results of evaluating the PRF inputs.
    /// </summary>
    [JsonPropertyName("results")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsPRFValues Results { get; init; }
}
