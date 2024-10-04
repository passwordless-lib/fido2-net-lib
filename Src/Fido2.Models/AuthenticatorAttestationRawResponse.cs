using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

public sealed class AuthenticatorAttestationRawResponse
{
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("id")]
    public byte[] Id { get; set; }

    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("rawId")]
    public byte[] RawId { get; set; }

    [JsonPropertyName("type")]
    public PublicKeyCredentialType? Type { get; set; }

    [JsonPropertyName("response")]
    public AttestationResponse Response { get; set; }

    [JsonPropertyName("extensions")]
    [Obsolete("Use ClientExtensionResults instead")]
    public AuthenticationExtensionsClientOutputs Extensions
    {
        get => ClientExtensionResults;
        set => ClientExtensionResults = value;
    }

    [JsonPropertyName("clientExtensionResults")]
    public AuthenticationExtensionsClientOutputs ClientExtensionResults { get; set; }

    public sealed class AttestationResponse
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("attestationObject")]
        public byte[] AttestationObject { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("clientDataJSON")]
        public byte[] ClientDataJson { get; set; }

        [JsonPropertyName("transports")]
        public AuthenticatorTransport[] Transports { get; set; }
    }
}
