using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// One authenticator's <c>ConvenienceDetails</c> from the FIDO Alliance Convenience Metadata Service
/// (<see href="https://fidoalliance.org/specs/mds/fido-convenience-metadata-service-v1.0-ps-20250521.html">FIDO
/// Convenience Metadata Service v1.0</see> §3.1.2).
/// </summary>
public sealed class ConvenienceMetadataEntry
{
    /// <summary>
    /// Display names for this authenticator model, keyed by IETF language tag (e.g. <c>en-US</c>, which is mandatory).
    /// </summary>
    [JsonPropertyName("friendlyNames")]
    public Dictionary<string, string>? FriendlyNames { get; set; }

    /// <summary>
    /// A <c>data:</c> URL PNG or SVG icon of the authenticator, for a light background.
    /// </summary>
    [JsonPropertyName("icon")]
    public string? Icon { get; set; }

    /// <summary>
    /// A <c>data:</c> URL SVG icon of the authenticator, for a dark background.
    /// </summary>
    [JsonPropertyName("iconDark")]
    public string? IconDark { get; set; }

    /// <summary>
    /// A <c>data:</c> URL SVG logo of the provider (e.g. a passkey manager), for a light background. The spec asks
    /// Relying Parties to prefer <see cref="Icon"/> when both are present.
    /// </summary>
    [JsonPropertyName("providerLogoLight")]
    public string? ProviderLogoLight { get; set; }

    /// <summary>
    /// A <c>data:</c> URL SVG logo of the provider, for a dark background.
    /// </summary>
    [JsonPropertyName("providerLogoDark")]
    public string? ProviderLogoDark { get; set; }
}
