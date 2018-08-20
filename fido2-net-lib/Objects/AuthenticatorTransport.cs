using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{
    /// <summary>
    ///  Authenticators may implement various transports for communicating with clients. This enumeration defines hints as to how clients might communicate with a particular authenticator in order to obtain an assertion for a specific credential. Note that these hints represent the WebAuthn Relying Party's best belief as to how an authenticator may be reached. A Relying Party may obtain a list of transports hints from some attestation statement formats or via some out-of-band mechanism; it is outside the scope of this specification to define that mechanism. 
    /// </summary>
    public sealed class AuthenticatorTransport : TypedString
    {
        /// <summary>
        /// Indicates the respective authenticator can be contacted over removable USB.
        /// </summary>
        public static readonly AuthenticatorTransport Usb = new AuthenticatorTransport("usb");

        /// <summary>
        /// Indicates the respective authenticator can be contacted over Near Field Communication (NFC).
        /// </summary>
        public static readonly AuthenticatorTransport Nfc = new AuthenticatorTransport("nfc");

        /// <summary>
        /// Indicates the respective authenticator can be contacted over Bluetooth Smart(Bluetooth Low Energy / BLE)
        /// </summary>
        public static readonly AuthenticatorTransport Ble = new AuthenticatorTransport("ble");

        /// <summary>
        /// Indicates the respective authenticator is contacted using a client device-specific transport.These authenticators are not removable from the client device.
        /// </summary>
        public static readonly AuthenticatorTransport Internal = new AuthenticatorTransport("internal");

        private AuthenticatorTransport(string value) : base(value)
        {
        }
    }
}
