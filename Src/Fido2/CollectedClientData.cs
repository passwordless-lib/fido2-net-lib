using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib
{
    /// <summary>
    /// Base class for responses sent by the Authenticator Client
    /// </summary>
    public class CollectedClientData
    {
        protected CollectedClientData(ReadOnlySpan<byte> utf8EncodedJson)
        {
            if (utf8EncodedJson.Length is 0)
                throw new Fido2VerificationException("utf8EncodedJson may not be empty");

            // 1. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON

            // 2. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext
            // Note: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.
            // We call this AuthenticatorResponse
            CollectedClientData response;
            try
            {
                response = JsonSerializer.Deserialize<CollectedClientData>(utf8EncodedJson)!;
            }
            catch (Exception e) when (e is JsonException)
            {
                throw new Fido2VerificationException("Malformed clientDataJson");
            }

            if (response is null)
                throw new Fido2VerificationException("Deserialized authenticator response cannot be null");
            Type = response.Type;
            Challenge = response.Challenge;
            Origin = response.Origin;
            CrossOrigin = response.CrossOrigin;
        }

#nullable disable
        public CollectedClientData() // for deserialization
        {

        }
#nullable enable

        public const int MAX_ORIGINS_TO_PRINT = 5;

        [JsonPropertyName("type"), Required]
        public string Type { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("challenge"), Required]
        public byte[] Challenge { get; set; }

        [JsonPropertyName("origin"), Required]
        public string Origin { get; set; }

        [JsonPropertyName("crossOrigin")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public bool? CrossOrigin { get; set; }

        protected void BaseVerify(HashSet<string> fullyQualifiedExpectedOrigins, ReadOnlySpan<byte> originalChallenge)
        {
            if (Type is not "webauthn.create" && Type is not "webauthn.get")
                throw new Fido2VerificationException($"Type not equal to 'webauthn.create' or 'webauthn.get'. Was: '{Type}'");

            if (Challenge is null)
                throw new Fido2VerificationException("Challenge cannot be null");

            // 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call
            if (!Challenge.AsSpan().SequenceEqual(originalChallenge))
                throw new Fido2VerificationException("Challenge not equal to original challenge");

            var fullyQualifiedOrigin = Origin.ToFullyQualifiedOrigin();

            // 5. Verify that the value of C.origin matches the Relying Party's origin.
            if (!fullyQualifiedExpectedOrigins.Contains(fullyQualifiedOrigin))
                throw new Fido2VerificationException($"Fully qualified origin {fullyQualifiedOrigin} of {Origin} not equal to fully qualified original origin {string.Join(", ", fullyQualifiedExpectedOrigins.Take(MAX_ORIGINS_TO_PRINT))} ({fullyQualifiedExpectedOrigins.Count})");
        }
    }
}
