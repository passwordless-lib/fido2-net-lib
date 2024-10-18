using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// A WebAuthn Relying Party may require user verification for some of its operations but not for others,
/// and may use this type to express its needs.
/// https://www.w3.org/TR/webauthn-2/#enumdef-userverificationrequirement
/// </summary>
[JsonConverter(typeof(FidoEnumConverter<UserVerificationRequirement>))]
public enum UserVerificationRequirement
{
    /// <summary>
    /// This value indicates that the Relying Party requires user verification for the operation
    /// and will fail the operation if the response does not have the UV flag set.
    /// </summary>
    [EnumMember(Value = "required")]
    Required,

    /// <summary>
    /// This value indicates that the Relying Party prefers user verification for the operation if possible,
    /// but will not fail the operation if the response does not have the UV flag set.
    /// </summary>
    [EnumMember(Value = "preferred")]
    Preferred,

    /// <summary>
    /// This value indicates that the Relying Party does not want user verification employed during the operation
    /// (e.g., in the interest of minimizing disruption to the user interaction flow).
    /// </summary>
    [EnumMember(Value = "discouraged")]
    Discouraged
}
