using System.Collections.Generic;
using Fido2NetLib.Objects;
using System.Text.Json;
using System.Text.Json.Serialization;

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
        [JsonPropertyName("challenge")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Challenge { get; set; }

        /// <summary>
        /// This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete. This is treated as a hint, and MAY be overridden by the client.
        /// </summary>
        [JsonPropertyName("timeout")]
        public uint Timeout { get; set; }

        /// <summary>
        /// This OPTIONAL member specifies the relying party identifier claimed by the caller.If omitted, its value will be the CredentialsContainer object’s relevant settings object's origin's effective domain
        /// </summary>
        [JsonPropertyName("rpId")]
        public string RpId { get; set; }

        /// <summary>
        /// This OPTIONAL member contains a list of PublicKeyCredentialDescriptor objects representing public key credentials acceptable to the caller, in descending order of the caller’s preference(the first item in the list is the most preferred credential, and so on down the list)
        /// </summary>
        [JsonPropertyName("allowCredentials")]
        public IEnumerable<PublicKeyCredentialDescriptor> AllowCredentials { get; set; }

        /// <summary>
        /// This member describes the Relying Party's requirements regarding user verification for the get() operation. Eligible authenticators are filtered to only those capable of satisfying this requirement
        /// </summary>
        [JsonPropertyName("userVerification")]
        public UserVerificationRequirement? UserVerification { get; set; }

        /// <summary>
        /// This OPTIONAL member contains additional parameters requesting additional processing by the client and authenticator. For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.
        /// </summary>
        [JsonPropertyName("extensions")]
        public AuthenticationExtensionsClientInputs Extensions { get; set; }

        public static AssertionOptions Create(Fido2Configuration config, byte[] challenge, IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials, UserVerificationRequirement? userVerification, AuthenticationExtensionsClientInputs extensions)
        {
            return new AssertionOptions()
            {
                Status = "ok",
                ErrorMessage = string.Empty,
                Challenge = challenge,
                Timeout = config.Timeout,
                RpId = config.ServerDomain,
                AllowCredentials = allowedCredentials ?? new List<PublicKeyCredentialDescriptor>(),
                UserVerification = userVerification,
                Extensions = extensions
            };
        }

        public string ToJson()
        {
            return JsonSerializer.Serialize(this);
        }

        public static AssertionOptions FromJson(string json)
        {
            return JsonSerializer.Deserialize<AssertionOptions>(json);
        }
    }
}
