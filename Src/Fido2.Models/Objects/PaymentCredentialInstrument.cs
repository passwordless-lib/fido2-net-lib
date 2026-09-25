using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The payment instrument shown to the user during Secure Payment Confirmation, and signed with the transaction.
/// https://www.w3.org/TR/secure-payment-confirmation/#sctn-paymentcredentialinstrument-dictionary
/// </summary>
public sealed class PaymentCredentialInstrument
{
    /// <summary>
    /// The name of the instrument as displayed to the user, such as the card's last digits.
    /// </summary>
    [JsonPropertyName("displayName")]
    public required string DisplayName { get; init; }

    /// <summary>
    /// The URL of the instrument's icon. A data: URL lets the relying party sign exactly what the browser showed.
    /// </summary>
    [JsonPropertyName("icon")]
    public required string Icon { get; init; }

    /// <summary>
    /// Whether the request had to fail if the icon could not be fetched and shown. Defaults to <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// Settable rather than init-only on purpose: the source-generated serializer can only keep the default for an
    /// absent member if it can assign the property after construction.
    /// </remarks>
    [JsonPropertyName("iconMustBeShown")]
    public bool IconMustBeShown { get; set; } = true;

    /// <summary>
    /// Further detail about the instrument shown to the user, if any.
    /// </summary>
    [JsonPropertyName("details")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Details { get; init; }
}
