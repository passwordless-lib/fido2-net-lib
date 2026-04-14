using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/**
 * User Verification Methods Short Form
 *
 * The USER_VERIFY constants are flags in a bitfield represented as a 32 bit long integer. They describe the methods and capabilities of an UAF authenticator for locally verifying a user. The operational details of these methods are opaque to the server. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages.
 *
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#user-verification-methods
 */
#if NET9_0_OR_GREATER
[JsonConverter(typeof(JsonStringEnumConverter<UserVerificationMethods>))]
#else
[JsonConverter(typeof(FidoEnumConverter<UserVerificationMethods>))]
#endif
public enum UserVerificationMethods
{
    /// <summary>
    /// This flag must be set if the authenticator is able to confirm user presence in any fashion. If this flag and no other is set for user verification, the guarantee is only that the authenticator cannot be operated without some human intervention, not necessarily that the presence verification provides any level of authentication of the human's identity. (e.g. a device that requires a touch to activate)
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("presence_internal")]
#else
    [EnumMember(Value = "presence_internal")]
#endif
    PRESENCE_INTERNAL = 1,
    /// <summary>
    /// This flag must be set if the authenticator uses any type of measurement of a fingerprint for user verification.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("fingerprint_internal")]
#else
    [EnumMember(Value = "fingerprint_internal")]
#endif
    FINGERPRINT_INTERNAL = 2,
    /// <summary>
    /// This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("passcode_internal")]
#else
    [EnumMember(Value = "passcode_internal")]
#endif
    PASSCODE_INTERNAL = 4,
    /// <summary>
    /// This flag must be set if the authenticator uses a voiceprint (also known as speaker recognition) for user verification.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("voiceprint_internal")]
#else
    [EnumMember(Value = "voiceprint_internal")]
#endif
    VOICEPRINT_INTERNAL = 8,
    /// <summary>
    /// This flag must be set if the authenticator uses any manner of face recognition to verify the user.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("faceprint_internal")]
#else
    [EnumMember(Value = "faceprint_internal")]
#endif
    FACEPRINT_INTERNAL = 0x10,
    /// <summary>
    /// This flag must be set if the authenticator uses any form of location sensor or measurement for user verification.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("location_internal")]
#else
    [EnumMember(Value = "location_internal")]
#endif
    LOCATION_INTERNAL = 0x20,
    /// <summary>
    /// This flag must be set if the authenticator uses any form of eye biometrics for user verification.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("eyeprint_internal")]
#else
    [EnumMember(Value = "eyeprint_internal")]
#endif
    EYEPRINT_INTERNAL = 0x40,
    /// <summary>
    /// This flag must be set if the authenticator uses a drawn pattern for user verification.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("pattern_internal")]
#else
    [EnumMember(Value = "pattern_internal")]
#endif
    PATTERN_INTERNAL = 0x80,
    /// <summary>
    /// This flag must be set if the authenticator uses any measurement of a full hand (including palm-print, hand geometry or vein geometry) for user verification.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("handprint_internal")]
#else
    [EnumMember(Value = "handprint_internal")]
#endif
    HANDPRINT_INTERNAL = 0x100,
    /// <summary>
    /// This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification that might be gathered outside the authenticator boundary.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("passcode_external")]
#else
    [EnumMember(Value = "passcode_external")]
#endif
    PASSCODE_EXTERNAL = 0x800,
    /// <summary>
    /// This flag must be set if the authenticator uses a drawn pattern for user verification that might be gathered outside the authenticator boundary.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("pattern_external")]
#else
    [EnumMember(Value = "pattern_external")]
#endif
    PATTERN_EXTERNAL = 0x1000,
    /// <summary>
    /// This flag must be set if the authenticator will respond without any user interaction (e.g. Silent Authenticator).
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("none")]
#else
    [EnumMember(Value = "none")]
#endif
    NONE = 0x200,
    /// <summary>
    /// If an authenticator sets multiple flags for user verification types, it may also set this flag to indicate that all verification methods will be enforced (e.g. faceprint AND voiceprint). If flags for multiple user verification methods are set and this flag is not set, verification with only one is necessary (e.g. fingerprint OR passcode).
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("all")]
#else
    [EnumMember(Value = "all")]
#endif
    ALL = 0x400,
}
