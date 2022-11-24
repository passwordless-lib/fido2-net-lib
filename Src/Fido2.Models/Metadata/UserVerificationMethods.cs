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
[JsonConverter(typeof(FidoEnumConverter<UserVerificationMethods>))]
public enum UserVerificationMethods
{
    /// <summary>
    /// This flag must be set if the authenticator is able to confirm user presence in any fashion. If this flag and no other is set for user verification, the guarantee is only that the authenticator cannot be operated without some human intervention, not necessarily that the presence verification provides any level of authentication of the human's identity. (e.g. a device that requires a touch to activate)
    /// </summary>
    [EnumMember(Value = "presence_internal")]
    PRESENCE_INTERNAL = 1,
    /// <summary>
    /// This flag must be set if the authenticator uses any type of measurement of a fingerprint for user verification.
    /// </summary>
    [EnumMember(Value = "fingerprint_internal")]
    FINGERPRINT_INTERNAL = 2,
    /// <summary>
    /// This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification.
    /// </summary>
    [EnumMember(Value = "passcode_internal")]
    PASSCODE_INTERNAL = 4,
    /// <summary>
    /// This flag must be set if the authenticator uses a voiceprint (also known as speaker recognition) for user verification.
    /// </summary>
    [EnumMember(Value = "voiceprint_internal")]
    VOICEPRINT_INTERNAL = 8,
    /// <summary>
    /// This flag must be set if the authenticator uses any manner of face recognition to verify the user.
    /// </summary>
    [EnumMember(Value = "faceprint_internal")]
    FACEPRINT_INTERNAL = 0x10,
    /// <summary>
    /// This flag must be set if the authenticator uses any form of location sensor or measurement for user verification.
    /// </summary>
    [EnumMember(Value = "location_internal")]
    LOCATION_INTERNAL = 0x20,
    /// <summary>
    /// This flag must be set if the authenticator uses any form of eye biometrics for user verification.
    /// </summary>
    [EnumMember(Value = "eyeprint_internal")]
    EYEPRINT_INTERNAL = 0x40,
    /// <summary>
    /// This flag must be set if the authenticator uses a drawn pattern for user verification.
    /// </summary>
    [EnumMember(Value = "pattern_internal")]
    PATTERN_INTERNAL = 0x80,
    /// <summary>
    /// This flag must be set if the authenticator uses any measurement of a full hand (including palm-print, hand geometry or vein geometry) for user verification.
    /// </summary>
    [EnumMember(Value = "handprint_internal")]
    HANDPRINT_INTERNAL = 0x100,
    /// <summary>
    /// This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification that might be gathered outside the authenticator boundary.
    /// </summary>
    [EnumMember(Value = "passcode_external")]
    PASSCODE_EXTERNAL = 0x800,
    /// <summary>
    /// This flag must be set if the authenticator uses a drawn pattern for user verification that might be gathered outside the authenticator boundary.
    /// </summary>
    [EnumMember(Value = "pattern_external")]
    PATTERN_EXTERNAL = 0x1000,
    /// <summary>
    /// This flag must be set if the authenticator will respond without any user interaction (e.g. Silent Authenticator).
    /// </summary>
    [EnumMember(Value = "none")]
    NONE = 0x200,
    /// <summary>
    /// If an authenticator sets multiple flags for user verification types, it may also set this flag to indicate that all verification methods will be enforced (e.g. faceprint AND voiceprint). If flags for multiple user verification methods are set and this flag is not set, verification with only one is necessary (e.g. fingerprint OR passcode).
    /// </summary>
    [EnumMember(Value = "all")]
    ALL = 0x400,
}
