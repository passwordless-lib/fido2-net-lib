using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// How strictly a Relying Party enforces agreement between what an attestation claims and what the
/// authenticator's own FIDO Metadata Service statement says it is capable of. Governs every check described on
/// <see cref="Fido2Configuration.MetadataConsistencyStrictness"/>.
/// </summary>
/// <remarks>
/// Each individual check (backup eligibility, algorithm, transports, credential ID length, discoverability,
/// extensions -- see the remarks on <see cref="Fido2Configuration.MetadataConsistencyStrictness"/> for the full
/// list) is independently classified as <b>strong</b> (a direct contradiction with very low false-positive risk,
/// e.g. a credential ID longer than the authenticator's own declared maximum) or <b>weak</b> (a heuristic signal
/// authenticators and MDS statements are known to disagree on in ordinary, non-malicious use, e.g. reported
/// transports). That classification only changes what happens at <see cref="Standard"/>; every mismatch is
/// always logged (as of <see cref="LogOnly"/> and above) regardless of its tier or whether it ends up blocking
/// the ceremony.
/// </remarks>
#if NET9_0_OR_GREATER
[JsonConverter(typeof(JsonStringEnumConverter<MetadataConsistencyStrictness>))]
#else
[JsonConverter(typeof(FidoEnumConverter<MetadataConsistencyStrictness>))]
#endif
public enum MetadataConsistencyStrictness
{
    /// <summary>
    /// No metadata-consistency checks run at all. No metadata statement fields are even read for this purpose,
    /// so this has no performance cost beyond the metadata lookup already performed for trust-chain validation.
    /// Appropriate for a Relying Party that wants to accept any authenticator -- including synced credential
    /// providers / password managers, which routinely do not match a hardware authenticator's own metadata
    /// statement in every particular -- without any extra scrutiny.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("off")]
#endif
    [EnumMember(Value = "off")]
    Off,

    /// <summary>
    /// Every check runs and every mismatch is logged, but nothing is ever rejected because of one. Use this to
    /// observe how often real traffic disagrees with MDS metadata before turning on enforcement.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("log-only")]
#endif
    [EnumMember(Value = "log-only")]
    LogOnly,

    /// <summary>
    /// The default. Strong-tier mismatches reject the ceremony; weak-tier mismatches are logged only. Reasonable
    /// for most Relying Parties: it catches authenticators actively contradicting their own stated capabilities
    /// without false-positiving on the heuristic signals real, honest authenticators are known to get "wrong".
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("standard")]
#endif
    [EnumMember(Value = "standard")]
    Standard,

    /// <summary>
    /// Every mismatch, strong or weak, rejects the ceremony. For a Relying Party that wants to lock registration
    /// down to authenticators whose metadata statement agrees with everything observed about them -- accepting
    /// that this will also reject some honest authenticators over heuristic, non-malicious disagreements (see
    /// <see cref="Standard"/>).
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("strict")]
#endif
    [EnumMember(Value = "strict")]
    Strict
}
