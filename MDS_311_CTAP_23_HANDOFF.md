# MDS v3.1.1 & CTAP 2.3 Support

## Specifications

- [FIDO Metadata Service v3.1.1 (PS, 2026-01-05)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html)
- [FIDO Metadata Statement v3.1.1 (PS, 2026-01-05)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html)
- [CTAP 2.3 (PS, 2026-02-26)](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)

## What was implemented

### `AuthenticatorGetInfoResponse` (CTAP 2.3 §6.4)

The full response structure is now modelled and parsed, members `0x01`–`0x1F`.
Members added in CTAP 2.2/2.3:

| CBOR | Member | Type | Property |
|------|--------|------|----------|
| 0x18 | `longTouchForReset` | Boolean | `LongTouchForReset` |
| 0x19 | `encIdentifier` | Byte String | `EncIdentifier` |
| 0x1A | `transportsForReset` | Array of strings | `TransportsForReset` |
| 0x1B | `pinComplexityPolicy` | Boolean | `PinComplexityPolicy` |
| 0x1C | `pinComplexityPolicyURL` | Byte String | `PinComplexityPolicyUrl` |
| 0x1D | `maxPINLength` | Unsigned Integer | `MaxPinLength` |
| 0x1E | `encCredStoreState` | Byte String | `EncCredStoreState` |
| 0x1F | `authenticatorConfigCommands` | Array of Unsigned Integers | `AuthenticatorConfigCommands` |

Note `encIdentifier` is a **byte string** (`iv || ct`), not a GUID. The IV is regenerated on every
getInfo call, so the raw bytes differ between calls and MUST NOT be compared for equality.

### Version strings

Valid tokens are `FIDO_2_3`, `FIDO_2_1`, `FIDO_2_0`, `FIDO_2_1_PRE`, `U2F_V2`.

`FIDO_2_2` was **never defined** and MUST NOT appear in the `versions` member.

`Versions` is `string[]` of opaque tokens, so an unrecognized token needs no code change to
round-trip. `FromCborObject` ignores CBOR members it does not model, so responses from
authenticators implementing a newer revision still parse. Both properties are covered by tests.

### `MetadataStatement` (Metadata Statement v3.1.1)

New in v3.1.1: `iconDark`, `providerLogoLight`, `providerLogoDark`, `multiDeviceCredentialSupport`,
`cxConfigURL`. (`friendlyNames` already existed.)

### `perCredMgmtRO`

This is a CTAP getInfo **option ID**, living in the `options` map (`0x04`) — not a WebAuthn client
extension input and not a registration option. Read it via `Options["perCredMgmtRO"]`.

## Test coverage

- `Tests/Fido2.Ctap2.Tests/Responses/AuthenticatorGetInfoResponseTests.cs` — full getInfo response
  including the CTAP 2.2/2.3 members, an unrecognized version token, and an unmodelled CBOR member;
  plus a legacy `U2F_V2`-only authenticator.
- `Tests/Fido2.Models.Tests/Metadata/MetadataStatementSerializationTests.cs` — v3.1.1 wire names,
  tolerance of unknown members, and v3.0 statements omitting all v3.1.1 fields.

## Note for future work

An earlier draft of this branch added a large set of properties ("PIN Uproot", `uprootChallenge`,
`credentialBackup`, `credentialDisplayName`, `userIconUrl`, and similar) attributed to MDS v3.1.1 /
CTAP 2.3. None of these appear in the published specifications — the string `uproot` does not occur
anywhere in CTAP 2.3, and none of those fields exist in the Metadata Statement v3.1.1 dictionary.
They have been removed. Verify member names and CBOR keys against the linked specs before adding
more.
