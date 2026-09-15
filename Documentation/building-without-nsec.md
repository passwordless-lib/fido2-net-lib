# Building without NSec.Cryptography

Some organisations cannot take a dependency on `NSec.Cryptography` (or on the `libsodium` native library
it carries). This page describes how to build the library without it, and exactly what you give up.

## What NSec is used for

Only one thing: **Ed25519 signature verification**, for credentials whose COSE algorithm is `EdDSA` (-8)
or the fully-specified `Ed25519` (-19). It is confined to `CredentialPublicKey`, and nothing else in the
library touches it.

.NET does not provide Ed25519 in `System.Security.Cryptography` — this was still true as of .NET 10 —
so there is no in-box replacement to swap in.

## How to disable it

Build the library from source with the `DisableNSec` property set:

```bash
dotnet build Src/Fido2/Fido2.csproj -c Release -p:DisableNSec=true
```

This does two things:

1. Drops the `NSec.Cryptography` `PackageReference`.
2. Defines `FIDO2_DISABLE_NSEC`, which compiles out every NSec code path.

The resulting `Fido2.dll` has **no reference to NSec in its assembly metadata**, so neither the managed
assembly nor its native `libsodium` payload needs to be deployed.

## What changes

| Algorithm | Normal build | `DisableNSec=true` |
|---|---|---|
| ES256 / ES384 / ES512 / ES256K | verified | verified |
| RS256 / RS384 / RS512 / RS1 | verified | verified |
| PS256 / PS384 / PS512 | verified | verified |
| ML-DSA-44/65/87 (net10.0+) | verified | verified |
| **EdDSA (-8), Ed25519 (-19)** | **verified** | **`UnimplementedAlgorithm`** |
| Ed448 (-53) | `UnimplementedAlgorithm` | `UnimplementedAlgorithm` |

An EdDSA credential is refused the way Ed448 already is: a `Fido2VerificationException` with code
`UnimplementedAlgorithm` and a message naming the build switch. The refusal happens when the credential
public key is parsed, so a registration ceremony fails cleanly rather than part-way through verification.

Nothing else is affected. Attestation formats, metadata service, CTAP2 and the ASP.NET integration all
behave identically.

## What this means for your Relying Party

Do not offer EdDSA in `pubKeyCredParams`. If you leave it in the list, an authenticator may choose it,
and you will then be unable to verify the credential you just asked for. `PubKeyCredParam.Defaults`
includes EdDSA, so set the list explicitly:

```csharp
var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
{
    User = user,
    PubKeyCredParams =
    [
        PubKeyCredParam.ES256,
        PubKeyCredParam.RS256,
    ],
});
```

In practice this costs little: ES256 is universally supported by authenticators, and EdDSA is rare.

## Caveats

- This is a **source-build switch**, not a runtime one. The published NuGet package is built normally and
  does reference NSec; there is no way to opt out of a dependency that is already baked into a compiled
  assembly. If you need this, build the library yourself.
- The test suite is built normally and uses NSec directly to construct Ed25519 test keys, so
  `dotnet test` on a `DisableNSec=true` tree will not compile. Build `Src/Fido2/Fido2.csproj` on its own.
- If instead you want a package that never carries the dependency, the alternative is to move Ed25519
  behind a provider interface and ship it as a separate optional package. That is a public API change and
  has not been done.
