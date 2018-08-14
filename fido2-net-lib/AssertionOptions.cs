using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace fido2NetLib
{
    /// <summary>
    /// Sent to the browser when we want to Assert credentials and authenticate a user
    /// </summary>
    public class AssertionOptions
    {
        [JsonProperty("status")]
        public string Status { get; set; } = "ok";

        [JsonProperty("errorMessage")]
        public string ErrorMessage { get; set; } = string.Empty;

        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Challenge { get; set; }
        public uint Timeout { get; set; }
        public string RpId { get; set; }
        public List<PublicKeyCredentialDescriptor> AllowCredentials { get; set; } = new List<PublicKeyCredentialDescriptor>();
        public string UserVerification { get; set; } = "discouraged"; // todo: move to config for caller

        internal static AssertionOptions Create(byte[] challenge, List<PublicKeyCredentialDescriptor> allowedCredentials, Fido2NetLib.Configuration config)
        {
            return new AssertionOptions()
            {
                Challenge = challenge,
                Timeout = config.Timeout,
                RpId = config.ServerDomain,
                AllowCredentials = allowedCredentials
            };
        }

        // todo: Add Extensions
    }

    /// <summary>
    /// Lazy implementation of https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
    /// Should add validation of values as specified in spec
    /// </summary>
    public class PublicKeyCredentialDescriptor
    {
        public string Type { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Id { get; set; }
        public string[] Transports { get; set; } = new[] { "usb", "nfc", "ble" }; // Allow all transports for now
    };
}
