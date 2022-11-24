using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// This enumeration’s values describe the Relying Party's requirements for client-side discoverable credentials (formerly known as resident credentials or resident keys).
/// https://w3c.github.io/webauthn/#enum-residentKeyRequirement
/// </summary>
[JsonConverter(typeof(FidoEnumConverter<ResidentKeyRequirement>))]
public enum ResidentKeyRequirement
{
    /// <summary>
    /// The Relying Party requires a client-side discoverable credential. The client MUST return an error if a client-side discoverable credential cannot be created.
    /// </summary>
    [EnumMember(Value = "required")]
    Required,

    /// <summary>
    /// The Relying Party strongly prefers creating a client-side discoverable credential, but will accept a server-side credential. The client and authenticator SHOULD create a discoverable credential if possible. For example, the client SHOULD guide the user through setting up user verification if needed to create a discoverable credential. This takes precedence over the setting of userVerification.
    /// </summary>
    [EnumMember(Value = "preferred")]
    Preferred,

    /// <summary>
    /// The Relying Party prefers creating a server-side credential, but will accept a client-side discoverable credential. The client and authenticator SHOULD create a server-side credential if possible.
    /// </summary>
    [EnumMember(Value = "discouraged")]
    Discouraged
}
