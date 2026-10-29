using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// One entry from a local authenticator display-metadata JSON file, in the shape used by
/// <see href="https://github.com/passkeydeveloper/passkey-authenticator-aaguids"/>: a name plus a
/// light- and dark-mode icon.
/// </summary>
public sealed class LocalAuthenticatorDisplayEntry
{
    /// <summary>
    /// The authenticator model's display name.
    /// </summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>
    /// A <c>data:</c> URI icon for use on a light background.
    /// </summary>
    [JsonPropertyName("icon_light")]
    public string? IconLight { get; set; }

    /// <summary>
    /// A <c>data:</c> URI icon for use on a dark background.
    /// </summary>
    [JsonPropertyName("icon_dark")]
    public string? IconDark { get; set; }
}
