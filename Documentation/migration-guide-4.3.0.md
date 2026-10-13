# Upgrade Guide: FIDO2 .NET Library v4.2.x → v4.3.0

This guide covers the behavioural changes in v4.3.0, which backports two WebAuthn Level 3 validation
checks from the 5.0.0-preview line to the 4.x line ([#689](https://github.com/passwordless-lib/fido2-net-lib/issues/689)).

## Overview

v4.3.0 does not change any API surface. It adds two checks to registration and authentication
ceremony verification that v4.2.x did not perform.

## Behavioural Changes (Won't Show Up as Compiler Errors)

These changes compile silently but change what your application does. Review them even if your
build is clean.

### Cross-origin ceremonies are now rejected by default

Previously, the library never inspected `clientDataJSON`'s `crossOrigin`/`topOrigin` fields at all,
so a ceremony performed inside a cross-origin iframe (one not same-origin with its top-level page)
was accepted unconditionally.

v4.3.0 validates both fields per WebAuthn L3 §7.1/§7.2:

- A response with `crossOrigin: true` now throws `Fido2VerificationException`
  (`Fido2ErrorCode.CrossOriginRequestNotAllowed`) unless you opt in.
- When present, `topOrigin` must match one of your configured `Origins`, or the ceremony throws
  `Fido2ErrorCode.InvalidAuthenticatorResponseTopOrigin`.

**If your application is never embedded in a cross-origin iframe**, this has no effect — browsers
only set `crossOrigin: true` in that scenario, so existing same-origin integrations are unaffected.

**If your application is intentionally used inside a cross-origin iframe** (e.g. an embedded
sign-in widget on a partner site), ceremonies that previously succeeded will now fail. Opt back in
explicitly:

```csharp
var config = new Fido2Configuration
{
    // ...
    AllowCrossOriginRequests = true,
};
```

`topOrigin` is still checked against your configured `Origins` regardless of this setting.

### An authenticator sending BS without BE is now rejected

Per WebAuthn L3 §7.1 step 15 / §7.2 step 16, a credential that is not backup-eligible (BE not set)
can never be backed up (BS set) — the combination is malformed. v4.2.x did not check this invariant
directly; it only evaluated your configured `BackupEligibleCredentialPolicy` /
`BackedUpCredentialPolicy`, so a permissive policy could let this combination through.

v4.3.0 rejects it unconditionally, before your backup policy is evaluated, with
`Fido2ErrorCode.InvalidBackupFlags`. In practice no conformant authenticator sends this
combination, so this should not affect real-world traffic; it only closes a gap a malformed or
malicious client could otherwise exploit.

## Migration Steps

1. If your application embeds the WebAuthn ceremony in a cross-origin iframe on purpose, set
   `AllowCrossOriginRequests = true` in your `Fido2Configuration` before upgrading.
2. Otherwise, no code changes are required.
