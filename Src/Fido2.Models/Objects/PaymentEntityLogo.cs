using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The logo of an entity facilitating a Secure Payment Confirmation transaction, as shown to the user.
/// https://www.w3.org/TR/secure-payment-confirmation/#sctn-paymententitylogo-dictionary
/// </summary>
public sealed class PaymentEntityLogo
{
    /// <summary>
    /// The URL of the logo. A data: URL lets the relying party sign exactly what the browser showed.
    /// </summary>
    [JsonPropertyName("url")]
    public required string Url { get; init; }

    /// <summary>
    /// A label for the logo, for accessibility and possibly display.
    /// </summary>
    [JsonPropertyName("label")]
    public required string Label { get; init; }
}
