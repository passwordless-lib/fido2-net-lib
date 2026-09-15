using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// How a Relying Party treats client or authenticator extension outputs it did not request.
/// </summary>
/// <remarks>
/// WebAuthn Level 3 explicitly allows both behaviours; see
/// <see cref="Fido2Configuration.UnsolicitedExtensionPolicy"/> for the relevant spec text.
/// </remarks>
#if NET9_0_OR_GREATER
[JsonConverter(typeof(JsonStringEnumConverter<UnsolicitedExtensionPolicy>))]
#else
[JsonConverter(typeof(FidoEnumConverter<UnsolicitedExtensionPolicy>))]
#endif
public enum UnsolicitedExtensionPolicy
{
    /// <summary>
    /// Unsolicited extension outputs are ignored. This is the default.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("ignore")]
#endif
    [EnumMember(Value = "ignore")]
    Ignore,

    /// <summary>
    /// Any extension output that was not requested fails the ceremony.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("reject")]
#endif
    [EnumMember(Value = "reject")]
    Reject
}
