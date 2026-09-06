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

        /// <summary>
        /// A copy of the authenticator data contained in <see cref="AttestationObject"/>, which
        /// <c>AuthenticatorAttestationResponse.toJSON()</c> includes so that a Relying Party can reach it
        /// without CBOR-decoding the attestation object.
        /// </summary>
        /// <remarks>
        /// This is an unverified copy supplied by the client. The library verifies the authenticator data
        /// inside <see cref="AttestationObject"/> and ignores this member; a Relying Party should do the same
        /// and read the verified values from the ceremony result.
        /// <para>
        /// <see href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorattestationresponsejson"/>
        /// </para>
        /// </remarks>
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("authenticatorData")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public byte[] AuthenticatorData { get; init; }

        /// <summary>
        /// A copy of the credential public key in DER SubjectPublicKeyInfo format. Absent when
        /// <c>pubKeyCredParams</c> negotiated an algorithm the user agent does not understand, in which case the
        /// key must be read from <see cref="AttestationObject"/> instead.
        /// </summary>
        /// <inheritdoc cref="AuthenticatorData" path="/remarks"/>
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("publicKey")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public byte[] PublicKey { get; init; }

        /// <summary>
        /// A copy of the COSE algorithm identifier of the new credential.
        /// </summary>
        /// <inheritdoc cref="AuthenticatorData" path="/remarks"/>
        [JsonPropertyName("publicKeyAlgorithm")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public COSE.Algorithm? PublicKeyAlgorithm { get; init; }
    }
}
