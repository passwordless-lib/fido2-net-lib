using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The <c>payment</c> member of the client data of a Secure Payment Confirmation ceremony: what the browser showed
/// the user and signed along with the challenge. At authentication every transaction detail is present; at
/// registration only <see cref="BrowserBoundPublicKey"/> may be.
/// https://www.w3.org/TR/secure-payment-confirmation/#sctn-collectedclientadditionalpaymentdata-dictionary
/// </summary>
public sealed class CollectedClientAdditionalPaymentData
{
    /// <summary>
    /// The RP ID of the relying party that created the credential.
    /// </summary>
    [JsonPropertyName("rpId")]
    public string? RpId { get; init; }

    /// <summary>
    /// The name some older implementations use for <see cref="RpId"/>. When both are present they must agree.
    /// </summary>
    [JsonPropertyName("rp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Rp { get; init; }

    /// <summary>
    /// The origin of the top-level page that asked to confirm the transaction: the merchant, when the relying party's
    /// code runs in an iframe there.
    /// </summary>
    [JsonPropertyName("topOrigin")]
    public string? TopOrigin { get; init; }

    /// <summary>
    /// The payee's name as shown to the user, if one was.
    /// </summary>
    [JsonPropertyName("payeeName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PayeeName { get; init; }

    /// <summary>
    /// The payee's origin as shown to the user, if one was.
    /// </summary>
    [JsonPropertyName("payeeOrigin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PayeeOrigin { get; init; }

    /// <summary>
    /// The logos shown to the user, in order, if any. The browser may show fewer than the relying party offered, but
    /// never any it did not.
    /// </summary>
    [JsonPropertyName("paymentEntitiesLogos")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public PaymentEntityLogo[]? PaymentEntitiesLogos { get; init; }

    /// <summary>
    /// The transaction total as shown to the user.
    /// </summary>
    [JsonPropertyName("total")]
    public PaymentCurrencyAmount? Total { get; init; }

    /// <summary>
    /// The payment instrument as shown to the user.
    /// </summary>
    [JsonPropertyName("instrument")]
    public PaymentCredentialInstrument? Instrument { get; init; }

    /// <summary>
    /// The browser-bound key's public key, as a base64url-encoded COSE_Key, when the browser holds one for the
    /// credential. Its signature over the client data arrives in the <c>payment</c> client extension output.
    /// </summary>
    [JsonPropertyName("browserBoundPublicKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BrowserBoundPublicKey { get; init; }
}
