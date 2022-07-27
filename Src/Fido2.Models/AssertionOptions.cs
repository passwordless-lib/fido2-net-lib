using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    /// <summary>
    /// https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions
    /// The PublicKeyCredentialRequestOptions dictionary supplies get() with the data it needs to generate an assertion. 
    /// Its challenge member MUST be present, while its other members are OPTIONAL.
    /// </summary>
    public class PublicKeyCredentialRequestOptions : Fido2ResponseBase
    {
        /// <summary>
        /// This member specifies a challenge that the authenticator signs, along with other data, when producing an authentication assertion.
        /// </summary>
        [JsonPropertyName("challenge"), Required]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Challenge { get; set; }

        /// <summary>
        /// This OPTIONAL member specifies a time, in milliseconds, that the Relying Party is willing to wait for the call to complete. The value is treated as a hint, and MAY be overridden by the client.
        /// </summary>
        [JsonPropertyName("timeout")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public uint? Timeout { get; set; }
#nullable enable
        /// <summary>
        /// This OPTIONAL member specifies the RP ID claimed by the Relying Party. The client MUST verify that the Relying Party's origin matches the scope of this RP ID. The authenticator MUST verify that this RP ID exactly equals the rpId of the credential to be used for the authentication ceremony.
        /// If not specified, its value will be the CredentialsContainer object’s relevant settings object's origin's effective domain.
        /// </summary>
        [JsonPropertyName("rpId")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? RpId { get; set; }

        /// <summary>
        /// This OPTIONAL member is used by the client to find authenticators eligible for this authentication ceremony.
        /// </summary>
        [JsonPropertyName("allowCredentials")]
        public IEnumerable<PublicKeyCredentialDescriptor>? AllowCredentials { get; set; }

        /// <summary>
        /// This OPTIONAL member specifies the Relying Party's requirements regarding user verification for the get() operation. The value SHOULD be a member of UserVerificationRequirement but client platforms MUST ignore unknown values, treating an unknown value as if the member does not exist. Eligible authenticators are filtered to only those capable of satisfying this requirement.
        /// </summary>
        [JsonPropertyName("userVerification")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public UserVerificationRequirement? UserVerification { get; set; }

        /// <summary>
        /// The Relying Party MAY use this OPTIONAL member to provide client extension inputs requesting additional processing by the client and authenticator.
        /// </summary>
        [JsonPropertyName("extensions")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public AuthenticationExtensionsClientInputs? Extensions { get; set; }
#nullable disable
        public static PublicKeyCredentialRequestOptions Create(Fido2Configuration config, byte[] challenge, IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials, AuthenticationExtensionsClientInputs extensions, UserVerificationRequirement? userVerification = UserVerificationRequirement.Preferred)
        {
            return new PublicKeyCredentialRequestOptions()
            {
                Status = "ok",
                ErrorMessage = string.Empty,
                Challenge = challenge,
                Timeout = config.Timeout,
                RpId = config.ServerDomain,
                AllowCredentials = allowedCredentials ?? Array.Empty<PublicKeyCredentialDescriptor>(),
                UserVerification = userVerification,
                Extensions = extensions
            };
        }

        public string ToJson()
        {
            return JsonSerializer.Serialize(this);
        }

        public static PublicKeyCredentialRequestOptions FromJson(string json)
        {
            return JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(json);
        }
    }
}
