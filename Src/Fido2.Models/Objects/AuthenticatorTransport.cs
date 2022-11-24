using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// Authenticators may implement various transports for communicating with clients. This enumeration defines hints as to how clients might communicate with a particular authenticator in order to obtain an assertion for a specific credential. Note that these hints represent the WebAuthn Relying Party's best belief as to how an authenticator may be reached. A Relying Party may obtain a list of transports hints from some attestation statement formats or via some out-of-band mechanism; it is outside the scope of this specification to define that mechanism. 
/// https://w3c.github.io/webauthn/#transport
/// </summary>
[JsonConverter(typeof(FidoEnumConverter<AuthenticatorTransport>))]
public enum AuthenticatorTransport
{
    /// <summary>
    /// Indicates the respective authenticator can be contacted over removable USB.
    /// </summary>
    [EnumMember(Value = "usb")]
    Usb,

    /// <summary>
    /// Indicates the respective authenticator can be contacted over Near Field Communication (NFC).
    /// </summary>
    [EnumMember(Value = "nfc")]
    Nfc,

    /// <summary>
    /// Indicates the respective authenticator can be contacted over Bluetooth Smart(Bluetooth Low Energy / BLE)
    /// </summary>
    [EnumMember(Value = "ble")]
    Ble,

    /// <summary>
    /// Indicates the respective authenticator is contacted using a client device-specific transport.These authenticators are not removable from the client device.
    /// </summary>
    [EnumMember(Value = "internal")]
    Internal,
}
