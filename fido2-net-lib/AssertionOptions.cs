using System;
using System.Collections.Generic;
using Fido2NetLib.Objects;
using Newtonsoft.Json;

namespace Fido2NetLib
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
        public IEnumerable<PublicKeyCredentialDescriptor> AllowCredentials { get; set; }
        public UserVerificationRequirement UserVerification { get; set; }

        internal static AssertionOptions Create(Fido2.Configuration config, byte[] challenge, IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials, UserVerificationRequirement userVerification)
        {
            return new AssertionOptions()
            {
                Challenge = challenge,
                Timeout = config.Timeout,
                RpId = config.ServerDomain,
                AllowCredentials = allowedCredentials ?? new List<PublicKeyCredentialDescriptor>(),
                UserVerification = userVerification
            };
        }

        // todo: Add Extensions
    }

    
}
