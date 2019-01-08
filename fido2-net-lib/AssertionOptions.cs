using System.Collections.Generic;
using Fido2NetLib.Objects;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Fido2NetLib
{
    /// <summary>
    /// Sent to the browser when we want to Assert credentials and authenticate a user
    /// </summary>
    public class AssertionOptions : Fido2ResponseBase
    {
        /// <summary>
        /// This member represents a challenge that the selected authenticator signs, along with other data, when producing an authentication assertion.See the §13.1 Cryptographic Challenges security consideration.
        /// </summary>
        [JsonProperty("challenge")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Challenge { get; set; }

        /// <summary>
        /// This member represents a challenge that the selected authenticator signs, along with other data, when producing an authentication assertion.See the §13.1 Cryptographic Challenges security consideration
        /// </summary>
        [JsonProperty("timeout")]
        public uint Timeout { get; set; }

        /// <summary>
        /// This OPTIONAL member specifies the relying party identifier claimed by the caller.If omitted, its value will be the CredentialsContainer object’s relevant settings object's origin's effective domain
        /// </summary>
        [JsonProperty("rpId")]
        public string RpId { get; set; }

        /// <summary>
        /// This OPTIONAL member contains a list of PublicKeyCredentialDescriptor objects representing public key credentials acceptable to the caller, in descending order of the caller’s preference(the first item in the list is the most preferred credential, and so on down the list)
        /// </summary>
        [JsonProperty("allowCredentials")]
        public IEnumerable<PublicKeyCredentialDescriptor> AllowCredentials { get; set; }

        /// <summary>
        /// This member describes the Relying Party's requirements regarding user verification for the get() operation. Eligible authenticators are filtered to only those capable of satisfying this requirement
        /// </summary>
        [JsonProperty("userVerification")]
        [JsonConverter(typeof(StringEnumConverter))]
        public UserVerificationRequirement UserVerification { get; set; }

        internal static AssertionOptions Create(Fido2.Configuration config, byte[] challenge, IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials, UserVerificationRequirement userVerification)
        {
            return new AssertionOptions()
            {
                Status = "ok",
                ErrorMessage = string.Empty,
                Challenge = challenge,
                Timeout = config.Timeout,
                RpId = config.ServerDomain,
                AllowCredentials = allowedCredentials ?? new List<PublicKeyCredentialDescriptor>(),
                UserVerification = userVerification
            };
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this);
        }

        public static AssertionOptions FromJson(string json)
        {
            return JsonConvert.DeserializeObject<AssertionOptions>(json);
        }

        // TODO: Add Extensions
    }


}
