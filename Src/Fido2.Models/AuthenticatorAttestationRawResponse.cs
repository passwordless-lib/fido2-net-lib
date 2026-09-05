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

    [JsonPropertyName("type"), Required]
    public PublicKeyCredentialType Type { get; init; }

    [JsonPropertyName("response"), Required]
    public AttestationResponse Response { get; init; }

    /// <summary>
    /// The attachment modality the client reported for the authenticator that handled this ceremony, or
    /// <see langword="null"/> if the client did not report one or reported a value this library does not
    /// recognize.
    /// </summary>
    /// <remarks>
    /// This value is supplied by the client and is not part of the signed authenticator data, so it is
    /// informational only and MUST NOT be relied upon as a security signal.
    /// </remarks>
    [JsonConverter(typeof(AuthenticatorAttachmentConverter))]
    [JsonPropertyName("authenticatorAttachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticatorAttachment? AuthenticatorAttachment { get; init; }

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

        /// <summary>
        /// The value returned from the client's <c>getTransports()</c>. Values the library does not recognize are
        /// discarded rather than rejected; see <see cref="AuthenticatorTransportArrayConverter"/>.
        /// </summary>
        [JsonConverter(typeof(AuthenticatorTransportArrayConverter))]
        [JsonPropertyName("transports"), Required]
        public AuthenticatorTransport[] Transports { get; init; }
    }
}
