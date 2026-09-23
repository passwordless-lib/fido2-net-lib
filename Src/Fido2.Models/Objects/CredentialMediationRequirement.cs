using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The mediation requirement a Relying Party passed to <c>navigator.credentials.create()</c> or
/// <c>navigator.credentials.get()</c>. Defined by Credential Management, not WebAuthn, but WebAuthn's
/// registration ceremony depends on it.
/// </summary>
/// <remarks>
/// The only value WebAuthn treats specially is <see cref="Conditional"/>: "If options.mediation is not set to
/// conditional, verify that the UP bit of the flags in authData is set" -- a conditional create (used for
/// upgrading an existing password login to a passkey) may complete without a user presence test.
/// See step 15 of <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential"/>.
/// </remarks>
#if NET9_0_OR_GREATER
[JsonConverter(typeof(JsonStringEnumConverter<CredentialMediationRequirement>))]
#else
[JsonConverter(typeof(FidoEnumConverter<CredentialMediationRequirement>))]
#endif
public enum CredentialMediationRequirement
{
    /// <summary>
    /// The user agent will not show any UI; the ceremony fails if it cannot complete silently.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("silent")]
#endif
    [EnumMember(Value = "silent")]
    Silent,

    /// <summary>
    /// The user agent shows UI only if needed. This is the default for both ceremonies.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("optional")]
#endif
    [EnumMember(Value = "optional")]
    Optional,

    /// <summary>
    /// The ceremony is surfaced passively -- as autofill suggestions for an authentication, or alongside an
    /// existing sign-in for a registration -- rather than as a modal prompt.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("conditional")]
#endif
    [EnumMember(Value = "conditional")]
    Conditional,

    /// <summary>
    /// The user agent always shows UI, even when it could complete the ceremony without it.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("required")]
#endif
    [EnumMember(Value = "required")]
    Required
}
