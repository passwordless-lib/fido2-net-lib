# Secure Payment Confirmation

[Secure Payment Confirmation](https://www.w3.org/TR/secure-payment-confirmation/) (SPC) lets a merchant ask the
user's bank to confirm a payment with a passkey: the browser shows the amount, the payee and the payment
instrument, the user confirms with their authenticator, and the resulting assertion signs those transaction details
along with the usual challenge. The relying party (the bank, or whoever issued the credential) then verifies that
what was signed is what it expected the user to see.

The library supports SPC on the relying party's side: creating credentials for it, and verifying the assertions it
produces. Invoking SPC itself happens in the browser through the Payment Request API and is outside the library's
scope.

## Registration

Create the credential as usual, with the `payment` extension marking it as usable for payments. Browsers currently
require a platform authenticator, a discoverable credential and user verification for such credentials:

```csharp
var options = fido2.RequestNewCredential(new RequestNewCredentialParams
{
    User = user,
    AuthenticatorSelection = new AuthenticatorSelection
    {
        AuthenticatorAttachment = AuthenticatorAttachment.Platform,
        ResidentKey = ResidentKeyRequirement.Required,
        UserVerification = UserVerificationRequirement.Required,
    },
    Extensions = new AuthenticationExtensionsClientInputs
    {
        Payment = new AuthenticationExtensionsPaymentInputs { IsPayment = true },
    },
});
```

Verify the response with `MakeNewCredentialAsync` as for any registration. If the browser registered a
[browser-bound key](https://www.w3.org/TR/secure-payment-confirmation/#sctn-browser-bound-key-store) alongside
the credential, its signature over the client data is verified and the key is returned in
`RegisteredPublicKeyCredential.BrowserBoundPublicKey`; store it if you want evidence later that the same browser
installation is confirming transactions.

## Authentication

The merchant (or the relying party's own iframe on the merchant's page) calls the Payment Request API with the
`secure-payment-confirmation` method, passing the challenge and credential IDs it obtained from the relying party,
and the transaction details to show. The assertion comes back to the relying party, which verifies it with
`MakeAssertionAsync`, telling the library what the user should have been shown:

```csharp
var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
{
    AssertionResponse = response,
    OriginalOptions = options,
    StoredPublicKey = credential.PublicKey,
    StoredSignatureCounter = credential.SignCount,
    IsUserHandleOwnerOfCredentialIdCallback = ...,
    SecurePaymentConfirmation = new SecurePaymentConfirmationExpectations
    {
        TopOrigin = "https://merchant.example",
        PayeeOrigin = "https://merchant.example",
        Total = new PaymentCurrencyAmount { Currency = "USD", Value = "10.00" },
        Instrument = new PaymentCredentialInstrument
        {
            DisplayName = "Visa ****1234",
            Icon = "https://bank.example/card.png",
        },
    },
});
```

With expectations supplied, the library follows
[§9.1 of the specification](https://www.w3.org/TR/secure-payment-confirmation/#sctn-verifying-assertion):

- the client data's type must be `payment.get`;
- `payment.rpId` must be the configured RP ID, and `payment.topOrigin` the expected top-level origin;
- `payment.payeeName` and `payment.payeeOrigin` must match what was expected, including being absent when
  nothing was to be shown;
- `payment.paymentEntitiesLogos` must be a subset of the offered logos, in the offered order (the browser may
  show fewer logos, never others);
- `payment.total` must be the expected amount -- compared as a number, so `10` and `10.00` agree -- in the
  expected currency;
- `payment.instrument` must be the expected instrument, including whether its icon had to be shown;
- if the client data names a browser-bound public key, the `payment` extension output must carry that key's
  signature over the client data, and it must verify. The key is then returned in
  `VerifyAssertionResult.BrowserBoundPublicKey`.

A mismatch throws `Fido2VerificationException` with `Fido2ErrorCode.InvalidPaymentData`.

### Who may call SPC

The client data's `origin` is that of the frame that called SPC. When the relying party's own iframe on the
merchant's page makes the call, that is the relying party's origin and the configured `Origins` apply. When the
merchant calls SPC directly, set `SecurePaymentConfirmationExpectations.Origins` to the merchant origins allowed
for that transaction; they replace the configured origins for that assertion only, so a login from a merchant's
origin is still refused.

### Payments are not logins

A payment assertion is a valid signature by the user's credential, so an attacker who obtains one could try to
post it to the login endpoint ([§11.1.1](https://www.w3.org/TR/secure-payment-confirmation/#sctn-login-attack)).
The library refuses a `payment.get` assertion whenever `SecurePaymentConfirmation` is not supplied, and refuses a
`webauthn.get` assertion whenever it is, so each endpoint only accepts the kind of assertion it is for.
