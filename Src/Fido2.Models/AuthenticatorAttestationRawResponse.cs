#nullable disable

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

public sealed class AuthenticatorAttestationRawResponse
{
    /// <summary>
    /// A string containing the credential's identifier. Base64UrlEncoding of <seealso cref="RawId"/>.
    /// </summary>
    [JsonPropertyName("id"), Required]
    public string Id { get; init; }

    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("rawId"), Required]
    public byte[] RawId { get; init; }

    /// <summary>
    /// Nullable so that a JSON payload omitting <c>type</c> entirely is distinguishable from one that explicitly
    /// sends <c>"public-key"</c> -- <see cref="PublicKeyCredentialType.PublicKey"/> is enum member zero, so a
    /// non-nullable field would silently default to it instead of failing the "type must be public-key" check.
    /// </summary>
    [JsonPropertyName("type"), Required]
    public PublicKeyCredentialType? Type { get; init; }

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
