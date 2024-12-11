#nullable disable

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Transport class for AssertionResponse
/// </summary>
public class AuthenticatorAssertionRawResponse
{
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("id"), Required]
    public byte[] Id { get; init; }

    // might be wrong to base64url encode this...
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("rawId"), Required]
    public byte[] RawId { get; init; }

    [JsonPropertyName("response")]
    public AssertionResponse Response { get; init; }

    [JsonPropertyName("type"), Required]
    public PublicKeyCredentialType Type { get; init; }

    [JsonPropertyName("extensions")]
    [Obsolete("Use ClientExtensionResults instead")]
    public AuthenticationExtensionsClientOutputs Extensions
    {
        get => ClientExtensionResults;
        set => ClientExtensionResults = value;
    }

    [JsonPropertyName("clientExtensionResults"), Required]
    public AuthenticationExtensionsClientOutputs ClientExtensionResults { get; set; }

#nullable enable

    public sealed class AssertionResponse
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("authenticatorData")]
        public required byte[] AuthenticatorData { get; init; }

        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("signature")]
        public required byte[] Signature { get; init; }

        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("clientDataJSON")]
        public required byte[] ClientDataJson { get; init; }

        [JsonPropertyName("userHandle")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[]? UserHandle { get; init; }
    }
}
