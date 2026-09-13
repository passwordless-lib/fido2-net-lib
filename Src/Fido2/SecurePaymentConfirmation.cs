using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Globalization;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// The Secure Payment Confirmation checks a relying party makes on top of WebAuthn's: that what the browser signed is
/// what the user should have been shown, and that any browser-bound key vouches for the client data.
/// https://www.w3.org/TR/secure-payment-confirmation/#sctn-verifying-assertion
/// </summary>
internal static class SecurePaymentConfirmation
{
    /// <summary>
    /// Verifies the <c>payment</c> member of an assertion's client data against what the relying party expected the
    /// user to see (SPC §9.1, the steps inserted after WebAuthn step 13).
    /// </summary>
    /// <param name="payment">The client data's <c>payment</c> member.</param>
    /// <param name="expected">What the relying party expected.</param>
    /// <param name="rpId">The relying party's RP ID, which the credential was created under.</param>
    /// <exception cref="Fido2VerificationException">A member is missing or differs from what was expected.</exception>
    public static void VerifyTransaction(CollectedClientAdditionalPaymentData? payment, SecurePaymentConfirmationExpectations expected, string rpId)
    {
        if (payment is null)
            throw Mismatch("the client data has no payment member");

        // "For historical reasons, some implementations may additionally include this parameter with the name rp.
        // The values of rp and rpId must be the same if both are present."
        string? claimedRpId = payment.RpId ?? payment.Rp;

        if (payment.RpId is not null && payment.Rp is not null && !string.Equals(payment.RpId, payment.Rp, StringComparison.Ordinal))
            throw Mismatch($"rpId '{payment.RpId}' and rp '{payment.Rp}' disagree");

        // Verify that the value of C["payment"]["rpId"] matches the Relying Party's origin.
        if (claimedRpId is null || !string.Equals(claimedRpId, rpId, StringComparison.OrdinalIgnoreCase))
            throw Mismatch($"rpId '{claimedRpId}' is not '{rpId}'");

        // Verify that the value of C["payment"]["topOrigin"] matches the top-level origin that the Relying Party expects.
        if (payment.TopOrigin is null || !OriginsEqual(payment.TopOrigin, expected.TopOrigin))
            throw Mismatch($"topOrigin '{payment.TopOrigin}' is not '{expected.TopOrigin}'");

        // Verify that the value of C["payment"]["payeeName"] matches the name of the payee that should have been displayed to the user, if any.
        if (!string.Equals(payment.PayeeName, expected.PayeeName, StringComparison.Ordinal))
            throw Mismatch($"payeeName '{payment.PayeeName}' is not '{expected.PayeeName}'");

        // Verify that the value of C["payment"]["payeeOrigin"] matches the origin of the payee that should have been displayed to the user, if any.
        if ((payment.PayeeOrigin is null) != (expected.PayeeOrigin is null) || (payment.PayeeOrigin is not null && !OriginsEqual(payment.PayeeOrigin, expected.PayeeOrigin!)))
            throw Mismatch($"payeeOrigin '{payment.PayeeOrigin}' is not '{expected.PayeeOrigin}'");

        // Verify that the value of C["payment"]["paymentEntitiesLogos"] is a strict and ordered subset of the logos that should have been displayed to the user, if any.
        if (!IsOrderedSubset(payment.PaymentEntitiesLogos, expected.PaymentEntitiesLogos))
            throw Mismatch("paymentEntitiesLogos are not the logos, or not in the order, offered to the user");

        // Verify that the value of C["payment"]["total"] matches the transaction amount that should have been displayed to the user.
        if (payment.Total is null || !AmountsEqual(payment.Total, expected.Total))
            throw Mismatch($"total '{payment.Total?.Value} {payment.Total?.Currency}' is not '{expected.Total.Value} {expected.Total.Currency}'");

        // Verify that the value of C["payment"]["instrument"] matches the payment instrument details that should have been displayed to the user.
        if (payment.Instrument is null || !InstrumentsEqual(payment.Instrument, expected.Instrument))
            throw Mismatch("instrument is not the one the user should have been shown");
    }

    /// <summary>
    /// Verifies the browser-bound key's signature over the client data, when the browser supplied one.
    /// </summary>
    /// <param name="payment">The client data's <c>payment</c> member, carrying the public key.</param>
    /// <param name="output">The <c>payment</c> client extension output, carrying the signature.</param>
    /// <param name="clientDataJson">The client data JSON, byte for byte as signed.</param>
    /// <returns>The browser-bound public key as a COSE_Key when both key and signature were present and the signature
    /// verified; <see langword="null"/> when neither was present.</returns>
    /// <exception cref="Fido2VerificationException">Only one of the key and signature is present, the key cannot be
    /// decoded, or the signature does not verify.</exception>
    public static byte[]? VerifyBrowserBoundSignature(CollectedClientAdditionalPaymentData? payment, AuthenticationExtensionsPaymentOutputs? output, ReadOnlySpan<byte> clientDataJson)
    {
        string? encodedKey = payment?.BrowserBoundPublicKey;
        byte[]? signature = output?.BrowserBoundSignature?.Signature;

        if (encodedKey is null && signature is null)
            return null;

        if (encodedKey is null)
            throw Mismatch("a browser-bound signature was returned but the client data names no browser-bound public key");

        if (signature is null)
            throw Mismatch("the client data names a browser-bound public key but no browser-bound signature was returned");

        byte[] coseKey;
        CredentialPublicKey key;

        try
        {
            coseKey = Base64Url.DecodeFromChars(encodedKey);
            key = new CredentialPublicKey(coseKey);
        }
        catch (Exception ex) when (ex is FormatException or Fido2VerificationException or InvalidCastException or KeyNotFoundException or System.Formats.Cbor.CborContentException)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidPaymentData, "The browser-bound public key is not a valid base64url-encoded COSE_Key", ex);
        }

        if (!key.Verify(clientDataJson, signature))
            throw Mismatch("the browser-bound signature does not verify over the client data");

        return coseKey;
    }

    private static Fido2VerificationException Mismatch(string detail)
    {
        return new Fido2VerificationException(Fido2ErrorCode.InvalidPaymentData, $"Secure Payment Confirmation data does not match the transaction: {detail}");
    }

    private static bool OriginsEqual(string actual, string expected)
    {
        return string.Equals(actual.ToFullyQualifiedOrigin(), expected.ToFullyQualifiedOrigin(), StringComparison.Ordinal);
    }

    private static bool AmountsEqual(PaymentCurrencyAmount actual, PaymentCurrencyAmount expected)
    {
        if (!string.Equals(actual.Currency, expected.Currency, StringComparison.OrdinalIgnoreCase))
            return false;

        // Both are "valid decimal monetary values" (Payment Request API), so "10" and "10.00" name the same amount
        if (decimal.TryParse(actual.Value, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out decimal a)
            && decimal.TryParse(expected.Value, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out decimal e))
        {
            return a == e;
        }

        return string.Equals(actual.Value, expected.Value, StringComparison.Ordinal);
    }

    private static bool InstrumentsEqual(PaymentCredentialInstrument actual, PaymentCredentialInstrument expected)
    {
        return string.Equals(actual.DisplayName, expected.DisplayName, StringComparison.Ordinal)
            && string.Equals(actual.Icon, expected.Icon, StringComparison.Ordinal)
            && actual.IconMustBeShown == expected.IconMustBeShown
            && string.Equals(actual.Details, expected.Details, StringComparison.Ordinal);
    }

    // Every logo the browser signed must be one the relying party offered, and in the order offered; the browser may leave some out.
    private static bool IsOrderedSubset(PaymentEntityLogo[]? shown, IReadOnlyList<PaymentEntityLogo>? offered)
    {
        if (shown is null || shown.Length == 0)
            return true;

        if (offered is null)
            return false;

        int next = 0;

        foreach (PaymentEntityLogo logo in shown)
        {
            while (next < offered.Count && !LogosEqual(logo, offered[next]))
                next++;

            if (next == offered.Count)
                return false;

            next++;
        }

        return true;
    }

    private static bool LogosEqual(PaymentEntityLogo a, PaymentEntityLogo b)
    {
        return string.Equals(a.Url, b.Url, StringComparison.Ordinal) && string.Equals(a.Label, b.Label, StringComparison.Ordinal);
    }
}
