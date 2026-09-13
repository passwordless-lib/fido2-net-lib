using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The input of the <c>payment</c> client extension. At registration, <see cref="IsPayment"/> marks the credential
/// as usable for Secure Payment Confirmation. The transaction details of an authentication are not set here: the
/// browser fills them in from the Payment Request, and they arrive in the client data's <c>payment</c> member.
/// https://www.w3.org/TR/secure-payment-confirmation/#sctn-payment-extension-registration
/// </summary>
public sealed class AuthenticationExtensionsPaymentInputs
{
    /// <summary>
    /// Whether the extension is active. Set it to <see langword="true"/> when creating a credential for payments.
    /// </summary>
    [JsonPropertyName("isPayment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? IsPayment { get; init; }

    /// <summary>
    /// The algorithms the browser may use for the browser-bound key, most preferred first. When absent, the browser
    /// uses the credential's own <c>pubKeyCredParams</c>.
    /// </summary>
    [JsonPropertyName("browserBoundPubKeyCredParams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public PubKeyCredParam[]? BrowserBoundPubKeyCredParams { get; init; }
}
