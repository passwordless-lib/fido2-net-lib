# Building without NSec.Cryptography

Some organisations cannot take a dependency on `NSec.Cryptography` (or on the `libsodium` native library
it carries). The `Fido2` package pulls it in by default so that EdDSA/Ed25519 credential support works out
of the box with nothing extra to install; **`Fido2.WithoutNSec` is the same library without that dependency.**

## Use `Fido2.WithoutNSec` instead of `Fido2`

```bash
dotnet add package Fido2.WithoutNSec
```

That's the whole change. It's the exact same source, the same `Fido2NetLib` namespace, the same public API --
just packaged without a transitive reference to `Fido2.NSec` (the package that supplies EdDSA support), so
`NSec.Cryptography` and its native `libsodium` payload never reach your dependency tree. Add `Fido2.WithoutNSec`
in place of `Fido2` in your project, not alongside it -- the two ship the library under different assembly
names precisely so this substitution is safe, but installing both in the same dependency graph is pointless
and not supported.

## What NSec is used for

Only one thing: **Ed25519 signature verification**, for credentials whose COSE algorithm is `EdDSA` (-8) or
the fully-specified `Ed25519` (-19). .NET does not provide Ed25519 in `System.Security.Cryptography` -- this
was still true as of .NET 10 -- so there is no in-box replacement to swap in.

## How this actually works

`CredentialPublicKey` never calls into `NSec.Cryptography` (or any other crypto library) directly for OKP
(EdDSA) keys. It dispatches through `IOkpSignatureVerifier`, an interface in `Fido2.Models`, looked up via a
small registry (`OkpSignatureVerifiers`). The `Fido2.NSec` package implements that interface and registers
itself automatically the moment its assembly loads -- nothing to configure in your own startup code either
way.

`Fido2` (the default package) declares a package dependency on `Fido2.NSec`, so it's present, loads, and
registers without you doing anything. `Fido2.WithoutNSec` is built from the identical source with that one
dependency omitted; nothing else differs. If no `IOkpSignatureVerifier` is registered when an OKP credential
is actually verified (not when it's merely parsed -- see below), verification fails cleanly with
`Fido2VerificationException`/`UnimplementedAlgorithm`, the same way an unsupported algorithm like Ed448
already does.

Constructing a `CredentialPublicKey` for an OKP credential never requires a provider to be registered --
only `Verify()` does. This means `Fido2.WithoutNSec` can still parse, store, and inspect an EdDSA credential
(e.g. to log its algorithm, or to reject it via `pubKeyCredParams` before ever reaching signature
verification); it just cannot verify a signature under it.

## What changes with `Fido2.WithoutNSec`

| Algorithm | `Fido2` | `Fido2.WithoutNSec` |
|---|---|---|
| ES256 / ES384 / ES512 / ES256K | verified | verified |
| RS256 / RS384 / RS512 / RS1 | verified | verified |
| PS256 / PS384 / PS512 | verified | verified |
| ML-DSA-44/65/87 (net10.0+) | verified | verified |
| **EdDSA (-8), Ed25519 (-19)** | **verified** | **`UnimplementedAlgorithm`** |
| Ed448 (-53) | `UnimplementedAlgorithm` -- no `IOkpSignatureVerifier` implements it yet | `UnimplementedAlgorithm` |

Nothing else is affected. Attestation formats, metadata service, CTAP2 and the ASP.NET integration all
behave identically.

## What this means for your Relying Party

If you're on `Fido2.WithoutNSec`, do not offer EdDSA in `pubKeyCredParams`. If you leave it in the list, an
authenticator may choose it, and you will then be unable to verify the credential you just asked for.
`PubKeyCredParam.Defaults` includes EdDSA, so set the list explicitly:

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

## Building from source instead

If you already build this library from source for other reasons, the same effect is available as an
MSBuild property rather than a separate package:

```bash
dotnet build Src/Fido2/Fido2.csproj -c Release -p:ExcludeFido2NSec=true
```

This is exactly the mechanism `Fido2.WithoutNSec` itself is packed with -- it drops the `Fido2.NSec`
project reference, so the resulting `Fido2.dll` carries no reference to `NSec.Cryptography` in its assembly
metadata at all (confirmed by inspection, not just by omission from the dependency list). The test suite
uses `NSec.Cryptography` directly to construct Ed25519 test fixtures, so `dotnet test` on a tree built this
way will not compile; build `Src/Fido2/Fido2.csproj` on its own, as the command above does.

## Adding EdDSA support back later

Nothing about this is permanent or one-way. A project on `Fido2.WithoutNSec` that later needs EdDSA can add
`Fido2.NSec` directly (`dotnet add package Fido2.NSec`) without switching back to `Fido2` -- the registration
is automatic either way, keyed only on whether the assembly is present at runtime, not on which top-level
package you asked for.
