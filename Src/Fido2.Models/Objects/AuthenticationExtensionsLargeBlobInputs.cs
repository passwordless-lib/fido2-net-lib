#nullable enable
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// Input values for the largeBlob extension.
///
/// Note: If a value is specified for <see cref="Write"/>, and the assertion is intended to be invoked on a web browser,
/// additional transformation must be performed on the client side before calling navigator.credentials.get().
/// Specifically, the value must be converted from a base64url-encoded string to a Uint8Array.
///
/// https://w3c.github.io/webauthn/#dictdef-authenticationextensionslargeblobinputs
/// </summary>
public sealed class AuthenticationExtensionsLargeBlobInputs
{
    /// <summary>
    /// Requests that the credential be created with largeBlob support.
    ///
    /// A value of <c>Required</c> will cause credential creation to fail on the client side if largeBlob support is not available.
    /// A value of <c>Preferred</c> will allow credential creation to succeed even if largeBlob support is not available.
    ///
    /// Valid only during registration.
    ///
    /// https://w3c.github.io/webauthn/#dom-authenticationextensionslargeblobinputs-support
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("support")]
    public LargeBlobSupport? Support { get; set; }

    /// <summary>
    /// Whether or not to read from the blob.
    ///
    /// Cannot be used in combination with <see cref="Write"/>.
    ///
    /// Valid only during assertion.
    ///
    /// https://w3c.github.io/webauthn/#dom-authenticationextensionslargeblobinputs-read
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("read")]
    public bool Read { get; set; }

    /// <summary>
    /// A blob to write to the authenticator.
    ///
    /// Cannot be used in combination with <see cref="Read"/>.
    ///
    /// Valid only during assertion.
    ///
    /// https://w3c.github.io/webauthn/#dom-authenticationextensionslargeblobinputs-write
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("write")]
    public byte[]? Write { get; set; }
}
