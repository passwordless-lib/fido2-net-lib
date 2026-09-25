using System.Collections.Generic;

namespace Fido2NetLib.Objects;

/// <summary>
/// What the relying party expects a Secure Payment Confirmation assertion to have shown the user. Supply it with the
/// assertion to verify a <c>payment.get</c> response; without it, such a response is refused, which keeps a payment
/// assertion from passing as a login.
/// https://www.w3.org/TR/secure-payment-confirmation/#sctn-verifying-assertion
/// </summary>
public sealed class SecurePaymentConfirmationExpectations
{
    /// <summary>
    /// The origin of the top-level page the transaction was confirmed on: usually the merchant.
    /// </summary>
    public required string TopOrigin { get; init; }

    /// <summary>
    /// The payee's name the user should have seen, or <see langword="null"/> if none was to be shown.
    /// </summary>
    public string? PayeeName { get; init; }

    /// <summary>
    /// The payee's origin the user should have seen, or <see langword="null"/> if none was to be shown.
    /// </summary>
    public string? PayeeOrigin { get; init; }

    /// <summary>
    /// The logos the user may have been shown, in order. The browser may show a subset, but no others.
    /// </summary>
    public IReadOnlyList<PaymentEntityLogo>? PaymentEntitiesLogos { get; init; }

    /// <summary>
    /// The transaction total the user should have seen.
    /// </summary>
    public required PaymentCurrencyAmount Total { get; init; }

    /// <summary>
    /// The payment instrument the user should have seen.
    /// </summary>
    public required PaymentCredentialInstrument Instrument { get; init; }

    /// <summary>
    /// The origins Secure Payment Confirmation may have been invoked from, when they differ from the relying party's
    /// own: a merchant that calls it directly, rather than through the relying party's iframe. When
    /// <see langword="null"/>, the configured origins apply.
    /// </summary>
    public IReadOnlySet<string>? Origins { get; init; }
}
