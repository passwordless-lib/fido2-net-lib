#nullable disable

using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Transport class for AssertionResponse
/// </summary>
public class AuthenticatorAssertionRawResponse
{
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("id")]
    public byte[] Id { get; set; }

    // might be wrong to base64url encode this...
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("rawId")]
    public byte[] RawId { get; set; }

    [JsonPropertyName("response")]
    public AssertionResponse Response { get; set; }

    [JsonPropertyName("type")]
    public PublicKeyCredentialType? Type { get; set; }

    [JsonPropertyName("extensions")]
    [Obsolete("Use ClientExtensionResults instead")]
    public AuthenticationExtensionsClientOutputs Extensions
    {
        get => ClientExtensionResults;
        set => ClientExtensionResults = value;
    }

    [JsonPropertyName("clientExtensionResults")]
    public AuthenticationExtensionsClientOutputs ClientExtensionResults { get; set; }

    public sealed class AssertionResponse
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("authenticatorData")]
        public byte[] AuthenticatorData { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("signature")]
        public byte[] Signature { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("clientDataJSON")]
        public byte[] ClientDataJson { get; set; }
#nullable enable
        [JsonPropertyName("userHandle")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[]? UserHandle { get; set; }

        [JsonPropertyName("attestationObject")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[]? AttestationObject { get; set; }
    }
}
