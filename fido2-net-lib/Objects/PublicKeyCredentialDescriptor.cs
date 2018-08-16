using System;
using System.Collections.Generic;
using System.Text;
using Fido2NetLib;
using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// Lazy implementation of https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
    /// todo: Should add validation of values as specified in spec
    /// </summary>
    public class PublicKeyCredentialDescriptor
    {
        public string Type { get; set; } = "public-key";

        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Id { get; set; }
        public string[] Transports { get; set; } = new[] { "usb", "nfc", "ble" }; // Allow all transports for now

        public PublicKeyCredentialDescriptor(byte[] credentialId)
        {
            Id = credentialId;
        }

        public PublicKeyCredentialDescriptor()
        {

        }
    };
}
