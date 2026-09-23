using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Represents the JSON resource served from an RP ID's <c>/.well-known/webauthn</c> endpoint, used by user
/// agents to validate <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">related origin requests</see>.
/// </summary>
public sealed class WellKnownWebAuthn
{
    /// <summary>
    /// The number of distinct <i>registrable origin labels</i> that a conforming WebAuthn Client is guaranteed to
    /// process: "WebAuthn Clients supporting this feature MUST support at least five registrable origin labels.
    /// Client policy SHOULD define an upper limit to prevent abuse."
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a floor on client behaviour, not a cap on how many origins a Relying Party may publish. The limit
    /// counts <i>labels</i>, not origins: the registrable origin label of a domain is the first domain label of
    /// its registrable domain, so <c>https://example.co.uk</c>, <c>https://www.example.de</c> and
    /// <c>https://example.sg</c> all share the single label <c>example</c> and together consume one of the five.
    /// A Relying Party can therefore publish many more than five origins, provided they fall under few enough
    /// labels.
    /// </para>
    /// <para>
    /// Determining a registrable domain requires the Public Suffix List, which this library does not carry, so it
    /// cannot count labels on your behalf. Order <see cref="Origins"/> with the most important labels first: a
    /// client walks the list in order and stops considering new labels once it reaches its limit.
    /// </para>
    /// </remarks>
    public const int MinimumClientSupportedLabels = 5;

    /// <inheritdoc cref="MinimumClientSupportedLabels"/>
    [Obsolete($"Renamed to {nameof(MinimumClientSupportedLabels)}. This value was previously used to truncate the published origin list, which was incorrect: the WebAuthn limit applies to registrable origin labels rather than origins, and it constrains clients rather than Relying Parties.")]
    public const int MaxOrigins = MinimumClientSupportedLabels;

    /// <summary>
    /// The set of origins, in addition to the RP ID's own origin, that are permitted to use this RP ID.
    /// </summary>
    [JsonPropertyName("origins")]
    public IReadOnlyList<string> Origins { get; set; } = [];
}
