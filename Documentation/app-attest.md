# Apple App Attest

[App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) lets an
iOS, iPadOS, macOS, tvOS or visionOS app prove to your server that its requests come from a genuine, unmodified
instance of the app on a genuine Apple device. The app creates a key in the Secure Enclave, has Apple attest it
once, and then signs requests with it.

App Attest borrows WebAuthn's attestation object and authenticator data formats, but it is not a WebAuthn
ceremony: there is no browser, no client data JSON, no origin, and no user presence test. Its data therefore does
not go through `MakeNewCredentialAsync` or `MakeAssertionAsync`, which would reject it for lacking the user
presence flag. The `AppAttest` class is the entry point instead.

```csharp
var appAttest = new AppAttest(new AppAttestConfiguration
{
    AppId = "ABCDE12345.com.example.app",              // <team ID>.<bundle ID>
    Environments = AppAttestEnvironment.Production      // add Development while testing from Xcode
});
```

## Attesting a key

1. The server issues a one-time challenge to the app and remembers it.
2. The app calls `DCAppAttestService.generateKey()`, then `attestKey(keyId, clientDataHash: SHA256(challenge))`,
   and sends the key ID and attestation object to the server.
3. The server verifies, computing the client data hash from the challenge *it* issued:

```csharp
var result = await appAttest.VerifyAttestationAsync(attestationObject, keyId, SHA256.HashData(challenge));

// store result.Key against the user or device: KeyId, PublicKey, Counter (0), Environment, Receipt
```

The library follows Apple's
[verification steps](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-attestation):
the certificate chain must reach Apple's App Attest root (development certificates, which expire within days,
are accepted after expiry as Apple's documentation allows); the nonce in the credential certificate must be the
SHA-256 of the authenticator data and the client data hash; the certificate's key must hash to the key ID; the
RP ID hash must be the SHA-256 of the configured App ID; the counter must be zero; the AAGUID must name an
accepted environment; and the credential ID must be the key ID. `result.TrustPath` carries the certificates and
`result.AttestationType` the kind of attestation established.

`result.Key.Receipt` is the receipt Apple issued; send it to Apple's servers for a
[fraud assessment](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk) if you use one.
The library does not interpret it.

## Verifying assertions

1. The app builds the request it wants to sign, embedding a fresh challenge from the server, and calls
   `generateAssertion(keyId, clientDataHash: SHA256(request))`.
2. It sends the request and the assertion to the server.
3. The server checks the challenge embedded in the request itself, hashes the request as received, and verifies:

```csharp
var result = appAttest.VerifyAssertion(assertion, SHA256.HashData(request), storedKey);

// store result.Key: the same key with Counter advanced
```

The signature must verify under the stored public key over the SHA-256 of the authenticator data and the
client data hash; the RP ID hash must be the configured App ID's; and the counter must be greater than the
stored one, which catches replays and cloned keys. Any failure throws `Fido2VerificationException` with a
`Fido2ErrorCode` naming the step.

## Trust anchor

`AppAttestConfiguration.TrustAnchor` defaults to `AppAttest.AppleRootCertificate`, Apple's App Attest root. It
can be replaced, which is how the library's own tests verify against a root of their own.
