using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The output of the <c>payment</c> client extension: the browser-bound key's signature, when the browser holds
/// such a key for the credential.
/// https://www.w3.org/TR/secure-payment-confirmation/#sctn-payment-extension-registration
/// </summary>
public sealed class AuthenticationExtensionsPaymentOutputs
{
    /// <summary>
    /// The signature the browser-bound key made over the client data, or <see langword="null"/> if the browser has
    /// no such key for the credential.
    /// </summary>
    [JsonPropertyName("browserBoundSignature")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public BrowserBoundSignature? BrowserBoundSignature { get; init; }
}

/// <summary>
/// A signature made with the browser-bound key: proof that the same browser installation that registered the
/// credential is the one confirming the transaction.
/// </summary>
public sealed class BrowserBoundSignature
{
    /// <summary>
    /// The signature over the client data JSON, base64url-encoded on the wire.
    /// </summary>
    [JsonPropertyName("signature")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public required byte[] Signature { get; init; }
}
