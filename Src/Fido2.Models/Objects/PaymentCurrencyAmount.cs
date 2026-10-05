using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// A monetary amount as the Payment Request API carries it: an ISO 4217 currency code and a decimal string.
/// https://www.w3.org/TR/payment-request/#paymentcurrencyamount-dictionary
/// </summary>
public sealed class PaymentCurrencyAmount
{
    /// <summary>
    /// The three-letter ISO 4217 currency code, such as <c>USD</c>.
    /// </summary>
    [JsonPropertyName("currency")]
    public required string Currency { get; init; }

    /// <summary>
    /// The amount as a decimal string, such as <c>10.00</c>; no thousands separators, and a period as the decimal point.
    /// </summary>
    [JsonPropertyName("value")]
    public required string Value { get; init; }
}
