﻿using System.Text.Json.Serialization;

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
    public PublicKeyCredentialType Type { get; set; } = PublicKeyCredentialType.PublicKey;

    [JsonPropertyName("response")]
    public AttestationResponse Response { get; set; }

    [JsonPropertyName("extensions")]
    public AuthenticationExtensionsClientOutputs Extensions { get; set; }

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
