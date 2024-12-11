#nullable disable

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

public sealed class AuthenticatorAttestationRawResponse
{
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("id"), Required]
    public byte[] Id { get; init; }

    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("rawId"), Required]
    public byte[] RawId { get; init; }

    [JsonPropertyName("type"), Required]
    public PublicKeyCredentialType Type { get; init; }

    [JsonPropertyName("response"), Required]
    public AttestationResponse Response { get; init; }

    [JsonPropertyName("extensions")]
    [Obsolete("Use ClientExtensionResults instead")]
    public AuthenticationExtensionsClientOutputs Extensions
    {
        get => ClientExtensionResults;
        set => ClientExtensionResults = value;
    }

    [JsonPropertyName("clientExtensionResults"), Required]
    public AuthenticationExtensionsClientOutputs ClientExtensionResults { get; set; }

    public sealed class AttestationResponse
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("attestationObject")]
        public required byte[] AttestationObject { get; init; }

        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("clientDataJSON")]
        public required byte[] ClientDataJson { get; init; }

        [JsonPropertyName("transports"), Required]
        public AuthenticatorTransport[] Transports { get; init; }
    }
}
