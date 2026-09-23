using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// A limited set of client capabilities which a Relying Party may evaluate to offer certain workflows and
/// experiences to users.
/// </summary>
/// <remarks>
/// The client reports these from <c>PublicKeyCredential.getClientCapabilities()</c>, which resolves to a map of
/// capability to boolean. Nothing in the ceremonies depends on them, so this library neither requests nor
/// verifies them; the enumeration is here so a Relying Party that forwards the client's answer to its server can
/// name the capabilities it cares about instead of matching raw strings.
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-clientCapability"/>
/// </para>
/// </remarks>
#if NET9_0_OR_GREATER
[JsonConverter(typeof(JsonStringEnumConverter<ClientCapability>))]
#else
[JsonConverter(typeof(FidoEnumConverter<ClientCapability>))]
#endif
public enum ClientCapability
{
    /// <summary>
    /// The WebAuthn Client is capable of conditional mediation for registration ceremonies.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("conditionalCreate")]
#endif
    [EnumMember(Value = "conditionalCreate")]
    ConditionalCreate,

    /// <summary>
    /// The WebAuthn Client is capable of conditional mediation for authentication ceremonies. Equivalent to <c>isConditionalMediationAvailable()</c> resolving to <see langword="true"/>.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("conditionalGet")]
#endif
    [EnumMember(Value = "conditionalGet")]
    ConditionalGet,

    /// <summary>
    /// The WebAuthn Client supports usage of the hybrid transport.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("hybridTransport")]
#endif
    [EnumMember(Value = "hybridTransport")]
    HybridTransport,

    /// <summary>
    /// The WebAuthn Client supports usage of a passkey platform authenticator, locally and/or via hybrid transport.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("passkeyPlatformAuthenticator")]
#endif
    [EnumMember(Value = "passkeyPlatformAuthenticator")]
    PasskeyPlatformAuthenticator,

    /// <summary>
    /// The WebAuthn Client supports usage of a user-verifying platform authenticator.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("userVerifyingPlatformAuthenticator")]
#endif
    [EnumMember(Value = "userVerifyingPlatformAuthenticator")]
    UserVerifyingPlatformAuthenticator,

    /// <summary>
    /// The WebAuthn Client supports Related Origin Requests.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("relatedOrigins")]
#endif
    [EnumMember(Value = "relatedOrigins")]
    RelatedOrigins,

    /// <summary>
    /// The WebAuthn Client supports <c>signalAllAcceptedCredentials()</c>.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("signalAllAcceptedCredentials")]
#endif
    [EnumMember(Value = "signalAllAcceptedCredentials")]
    SignalAllAcceptedCredentials,

    /// <summary>
    /// The WebAuthn Client supports <c>signalCurrentUserDetails()</c>.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("signalCurrentUserDetails")]
#endif
    [EnumMember(Value = "signalCurrentUserDetails")]
    SignalCurrentUserDetails,

    /// <summary>
    /// The WebAuthn Client supports <c>signalUnknownCredential()</c>.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("signalUnknownCredential")]
#endif
    [EnumMember(Value = "signalUnknownCredential")]
    SignalUnknownCredential
}
