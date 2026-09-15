#nullable disable

using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// An individual authenticator known to be rogue.
/// </summary>
/// <remarks>
/// Entries are published in the rogue list a <see cref="MetadataBLOBPayloadEntry.RogueListURL"/> points at, and
/// are removed again if the authenticator becomes known not to be rogue any longer.
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-rogue-list-entry"/>
/// </remarks>
public sealed class RogueListEntry
{
    /// <summary>
    /// Gets or sets the base64url encoding of the rogue authenticator's secret key (the <c>sk</c> value, see
    /// [FIDOEcdaaAlgorithm] section ECDAA Attestation). Revoking an individual authenticator requires its
    /// secret key to be known.
    /// </summary>
    [JsonPropertyName("sk")]
    public string Sk { get; set; }

    /// <summary>
    /// Gets or sets the ISO-8601 formatted date since when this entry is effective.
    /// </summary>
    [JsonPropertyName("date")]
    public string Date { get; set; }
}
