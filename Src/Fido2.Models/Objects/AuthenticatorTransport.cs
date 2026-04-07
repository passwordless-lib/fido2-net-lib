using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// Authenticators may implement various transports for communicating with clients.
/// This enumeration defines hints as to how clients might communicate with a particular
/// authenticator in order to obtain an assertion for a specific credential.
/// Note that these hints represent the WebAuthn Relying Party's best belief as to how an authenticator may be reached.
/// A Relying Party will typically learn of the supported transports for a public key credential via getTransports().
/// https://www.w3.org/TR/webauthn-2/#enum-transport
/// </summary>
[JsonConverter(typeof(FidoEnumConverter<AuthenticatorTransport>))]
public enum AuthenticatorTransport
{
    /// <summary>
    /// Indicates the respective authenticator can be contacted over removable USB.
    /// </summary>
    [EnumMember(Value = "usb")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("usb")]
#endif
    Usb,

    /// <summary>
    /// Indicates the respective authenticator can be contacted over Near Field Communication (NFC).
    /// </summary>
    [EnumMember(Value = "nfc")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("nfc")]
#endif
    Nfc,

    /// <summary>
    /// Indicates the respective authenticator can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
    /// </summary>
    [EnumMember(Value = "ble")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("ble")]
#endif
    Ble,

    /// <summary>
    /// Indicates the respective authenticator can be contacted over over ISO/IEC 7816 smart card with contacts.
    /// </summary>
    [EnumMember(Value = "smart-card")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("smart-card")]
#endif
    SmartCard,

    /// <summary>
    /// Indicates the respective authenticator can be contacted using a combination of (often separate) data-transport
    /// and proximity mechanisms. This supports, for example, authentication on a desktop computer using a smartphone.
    /// </summary>
    [EnumMember(Value = "hybrid")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("hybrid")]
#endif
    Hybrid,

    /// <summary>
    /// Indicates the respective authenticator is contacted using a client device-specific transport, i.e., it is a platform authenticator.
    /// These authenticators are not removable from the client device.
    /// </summary>
    [EnumMember(Value = "internal")]
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("internal")]
#endif
    Internal,
}
