#nullable enable
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// Output values for the largeBlob extension.
///
/// Note: If the assertion is intended to be run on a web browser, additional transformation must be performed
/// on the client extension output on the browser side after calling navigator.credentials.get(). Specifically,
/// the value of <c>largeBlob.blob</c> must be converted from a Uint8Array to a base64url-encoded string.
///
/// https://w3c.github.io/webauthn/#dictdef-authenticationextensionslargebloboutputs
/// </summary>
public sealed class AuthenticationExtensionsLargeBlobOutputs
{
    /// <summary>
    /// Whether or not the credential was created with largeBlob support.
    ///
    /// Valid only during registration.
    ///
    /// https://w3c.github.io/webauthn/#dom-authenticationextensionslargebloboutputs-supported
    /// </summary>
    [JsonPropertyName("supported")]
    public bool Supported { get; init; } = false;

    /// <summary>
    /// The blob read from the authenticator.
    ///
    /// Valid only during assertion.
    ///
    /// https://w3c.github.io/webauthn/#dom-authenticationextensionslargebloboutputs-blob
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("blob")]
    public byte[]? Blob { get; init; }

    /// <summary>
    /// Whether or not a blob was written to the authenticator.
    ///
    /// Valid only during assertion.
    ///
    /// https://w3c.github.io/webauthn/#dom-authenticationextensionslargebloboutputs-written
    /// </summary>
    [JsonPropertyName("written")]
    public bool Written { get; init; } = false;
}
