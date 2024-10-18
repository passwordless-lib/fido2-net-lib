using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
///  WebAuthn Relying Parties may use this enumeration to communicate hints to the user-agent about how a request may be best completed. These hints are not requirements, and do not bind the user-agent, but may guide it in providing the best experience by using contextual information that the Relying Party has about the request. Hints are provided in order of decreasing preference so, if two hints are contradictory, the first one controls. Hints may also overlap: if a more-specific hint is defined a Relying Party may still wish to send less specific ones for user-agents that may not recognise the more specific one. In this case the most specific hint should be sent before the less-specific ones.
/// Hints MAY contradict information contained in credential transports and authenticatorAttachment. When this occurs, the hints take precedence. (Note that transports values are not provided when using discoverable credentials, leaving hints as the only avenue for expressing some aspects of such a request.)
/// </summary>
[JsonConverter(typeof(FidoEnumConverter<PublicKeyCredentialHint>))]
public enum PublicKeyCredentialHint
{
    /// <summary>
    /// Indicates that the Relying Party believes that users will satisfy this request with a physical security key. For example, an enterprise Relying Party may set this hint if they have issued security keys to their employees and will only accept those authenticators for registration and authentication.
    /// </summary>
    [EnumMember(Value = "security-key")]
    SecurityKey,

    /// <summary>
    /// Indicates that the Relying Party believes that users will satisfy this request with a platform authenticator attached to the client device.
    /// </summary>
    [EnumMember(Value = "client-device")]
    ClientDevice,

    /// <summary>
    /// Indicates that the Relying Party believes that users will satisfy this request with general-purpose authenticators such as smartphones. For example, a consumer Relying Party may believe that only a small fraction of their customers possesses dedicated security keys. This option also implies that the local platform authenticator should not be promoted in the UI.
    /// </summary>
    [EnumMember(Value = "hybrid")]
    Hybrid,
}
