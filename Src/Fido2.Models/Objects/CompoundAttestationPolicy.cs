using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// How many of the sub-statements in a <c>compound</c> attestation statement must verify successfully for the
/// compound statement as a whole to be considered verified.
/// </summary>
/// <remarks>
/// WebAuthn Level 3 leaves this to the Relying Party: "If validation fails for one or more subStmt, decide the
/// appropriate result based on Relying Party policy. If sufficiently many (as determined by Relying Party policy)
/// items of attStmt verify successfully, return implementation-specific values representing any combination of
/// outputs from successful verification procedures."
/// See <see href="https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation"/>.
/// </remarks>
#if NET9_0_OR_GREATER
[JsonConverter(typeof(JsonStringEnumConverter<CompoundAttestationPolicy>))]
#else
[JsonConverter(typeof(FidoEnumConverter<CompoundAttestationPolicy>))]
#endif
public enum CompoundAttestationPolicy
{
    /// <summary>
    /// Every sub-statement must verify successfully. This is the default: a compound statement conveys several
    /// claims about the same credential, and accepting it while one of those claims is demonstrably false would
    /// discard evidence the authenticator went out of its way to provide.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("all")]
#endif
    [EnumMember(Value = "all")]
    RequireAll,

    /// <summary>
    /// At least one sub-statement must verify successfully. Use this to tolerate sub-statements in formats this
    /// library cannot verify, or formats that a particular deployment does not trust.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("any")]
#endif
    [EnumMember(Value = "any")]
    RequireAny
}
