# FIDO2 Metadata Service (MDS) Developer Guide

This guide explains how the FIDO2 Metadata Service (MDS) components work together and how to implement and register custom metadata services and repositories in the FIDO2 .NET Library.

## Architecture Overview

The MDS system follows a clean separation of concerns with two main layers:

```
IMetadataService (Caching/Access Layer)
    ↓
IMetadataRepository (Data Source Layer)
```

### Key Concepts

- **`IMetadataRepository`** - Handles the complexity of fetching, validating, and parsing metadata from various sources (FIDO Alliance, local files, conformance endpoints)
- **`IMetadataService`** - Provides a simple caching wrapper to allow sourcing attestation data from multiple repositories and support multi-level caching strategies
- **Registration API** - Fluent builder pattern for easy configuration and dependency injection

## Core Interfaces

### IMetadataService

The service layer provides a simple API for retrieving metadata entries:

```csharp
public interface IMetadataService
{
    /// <summary>
    /// Gets the metadata payload entry by AAGUID asynchronously.
    /// </summary>
    Task<MetadataBLOBPayloadEntry?> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a value indicating whether conformance testing mode is active. This should return false in production.
    /// </summary>
    bool ConformanceTesting();
}
```

### IMetadataRepository

The repository layer handles the heavy lifting of metadata retrieval and validation:

```csharp
public interface IMetadataRepository
{
    /// <summary>
    /// Downloads and validates the metadata BLOB from the source.
    /// </summary>
    Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a specific metadata statement from the BLOB.
    /// </summary>
    Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default);
}
```

## Built-in Implementations

### Repositories

| Repository                         | Purpose                     | Features                                         |
| ---------------------------------- | --------------------------- | ------------------------------------------------ |
| **Fido2MetadataServiceRepository** | Official FIDO Alliance MDS3 | JWT validation, certificate chains, CRL checking |
| **FileSystemMetadataRepository**   | Local file storage          | Fast local access, offline/development/testing   |
| **ConformanceMetadataRepository**  | FIDO conformance testing    | Multiple test endpoints, fake certificates       |

### Services

| Service                             | Purpose                    | Features                                               |
| ----------------------------------- | -------------------------- | ------------------------------------------------------ |
| **DistributedCacheMetadataService** | Production caching service | multi-tier caching (Memory → Distributed → Repository) |

## Quick Start

### Basic Setup with Official MDS

```csharp
services
    .AddFido2(config => {
        config.ServerName = "My FIDO2 Server";
        config.ServerDomain = "example.com";
        config.Origins = new HashSet<string> { "https://example.com" };
    })
    .AddFidoMetadataRepository()          // Official FIDO Alliance MDS
    .AddCachedMetadataService();          // 2-tier caching
```

### Multiple Repositories

```csharp
services
    .AddFido2(config => { /* ... */ })
    .AddFidoMetadataRepository()                    // Official MDS (primary)
    .AddFileSystemMetadataRepository("/mds/path") // Local files (fallback)
    .AddCachedMetadataService();                    // Caching wrapper
```

### Custom HTTP Client Configuration

```csharp
services
    .AddFido2(config => { /* ... */ })
    .AddFidoMetadataRepository(httpBuilder => {
        httpBuilder.ConfigureHttpClient(client => {
            client.Timeout = TimeSpan.FromSeconds(30);
        });
        httpBuilder.AddRetryPolicy();
    })
    .AddCachedMetadataService();
```

## Custom Implementation Guide

### Creating a Custom Repository

Implement `IMetadataRepository` to create your own metadata source:

```csharp
public class DatabaseMetadataRepository : IMetadataRepository
{
    private readonly IDbContext _context;
    private readonly ILogger<DatabaseMetadataRepository> _logger;

    public DatabaseMetadataRepository(IDbContext context, ILogger<DatabaseMetadataRepository> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Loading metadata BLOB from database");
        // TODO: Implement
    }

    public Task<MetadataStatement?> GetMetadataStatementAsync(
        MetadataBLOBPayload blob,
        MetadataBLOBPayloadEntry entry,
        CancellationToken cancellationToken = default)
    {
        // Statement is already loaded in the entry from GetBLOBAsync
        return Task.FromResult(entry.MetadataStatement);
    }
}
```

### Creating a Custom Service

Implement `IMetadataService` for custom caching strategies:

```csharp
public class SimpleMetadataService : IMetadataService
{
    private readonly IEnumerable<IMetadataRepository> _repositories;
    private readonly ILogger<SimpleMetadataService> _logger;
    private readonly ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry?> _cache = new();
    private DateTime _lastRefresh = DateTime.MinValue;
    private readonly TimeSpan _refreshInterval = TimeSpan.FromHours(6);

    public SimpleMetadataService(
        IEnumerable<IMetadataRepository> repositories,
        ILogger<SimpleMetadataService> logger)
    {
        _repositories = repositories;
        _logger = logger;
    }

    public async Task<MetadataBLOBPayloadEntry?> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default)
    {
        await RefreshIfNeededAsync(cancellationToken);
        return _cache.TryGetValue(aaguid, out var entry) ? entry : null;
    }

    public bool ConformanceTesting() => false;

    private async Task RefreshIfNeededAsync(CancellationToken cancellationToken)
    {
        foreach (var repository in _repositories)
        {
            try
            {
                var blob = await repository.GetBLOBAsync(cancellationToken);
                foreach (var entry in blob.Entries)
                {
                    // Cache it
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to refresh from repository {Repository}", repository.GetType().Name);
            }
        }
    }
}
```

### Registration

Register your custom implementations:

```csharp
// Register custom service + repository
services
    .AddFido2(config => { /* ... */ })
    .AddMetadataRepository<DatabaseMetadataRepository>()  // Custom repository
    .AddMetadataService<SimpleMetadataService>();         // Custom service

// Register custom service
services
    .AddFido2(config => { /* ... */ })
    .AddFidoMetadataRepository()  // FIDO Alliance repository
    .AddMetadataService<SimpleMetadataService>();         // Custom service


// Or use with built-in caching service
services
    .AddFido2(config => { /* ... */ })
    .AddMetadataRepository<DatabaseMetadataRepository>()  // Custom repository
    .AddCachedMetadataService();                          // Built-in caching
```

## Admin controls

Everything here is off by default; existing behaviour does not change until a setting is turned on. All of it is on
`Fido2Configuration`, so it can come from `appsettings.json` through `AddFido2(configuration.GetSection("fido2"))`:

```json
{
  "fido2": {
    "aaguidDenyList": [ "cb69481e-8ff7-4039-93ec-0a2729a154a8" ],
    "aaguidAllowList": [ "ee882879-721c-4913-9775-3dfcce97072a" ],
    "recheckMetadataStatusOnAssertion": true,
    "backupFlagMetadataConsistencyPolicy": "Enforce"
  }
}
```

### Allowing and denying authenticator models

- **`AaguidDenyList`** rejects a model at registration, and at sign-in for any credential whose AAGUID you pass as
  `MakeAssertionParams.StoredAaGuid` (store `RegisteredPublicKeyCredential.AaGuid` at registration). Adding a model
  therefore also locks out the credentials already registered with it. Rejections carry `Fido2ErrorCode.AaguidDenied`.
- **`AaguidAllowList`**, when non-empty, accepts only the listed models at registration (`AaguidNotAllowed`
  otherwise). It is not re-applied at sign-in; use the deny list to withdraw a model from existing users.

An AAGUID is reported by the authenticator itself. Unless the attestation proves it, it is whatever the authenticator
(or a modified client) chose to send, so:

- the deny list stops a model that identifies itself honestly -- a recalled product, a model you do not support --
  but not an authenticator that lies about what it is;
- the allow list, by default (`AaguidAllowListRequiresAttestation = true`), only accepts an AAGUID the attestation
  proves: a basic or attestation-CA attestation whose certificate chain validated against the attestation roots in
  that model's metadata statement. Anything else -- `none` or self attestation, a model with no metadata, a chain
  only checked against the certificate the authenticator sent -- fails with `AaguidNotAttested`. To use an allow
  list you therefore need a metadata service and registration options that ask for attestation
  (`AttestationConveyancePreference.Direct` or `Enterprise`). Set `AaguidAllowListRequiresAttestation = false` only
  if the list is a convenience filter rather than a security control.

### Re-checking metadata status at sign-in

The registration ceremony rejects models whose latest MDS status report is in `UndesiredAuthenticatorMetadataStatuses`
(revoked, key compromise, and so on). A model revoked *after* registration is only caught if
`RecheckMetadataStatusOnAssertion` is on and the assertion passes `StoredAaGuid`; a call without it skips the
re-check and logs event 1204 so the omission is visible. Like the registration check, the re-check only acts on a
status report the metadata service has: models with no metadata entry (most synced passkey providers) and every
credential during a metadata outage pass. FIDO U2F authenticators have no AAGUID -- their metadata is keyed by
attestation certificate -- and are not re-checked.

### Backup eligibility against metadata

With `BackupFlagMetadataConsistencyPolicy = Enforce`, a backup-eligible (BE) credential is rejected
(`BackupEligibilityNotDeclaredInMetadata`) when the model's metadata statement says its keys never leave the
authenticator. The statement's `multiDeviceCredentialSupport` is `"unsupported"`, `"explicit"` or `"implicit"`, and
a statement that omits it means `"unsupported"` (FIDO Metadata Statement v3.1 §4). Most statements in the live BLOB
predate the field, so enforcing this rejects BE credentials from every such model. A model with no statement has
made no claim and is not rejected.

### Ceremony logging

`Fido2` logs each ceremony's outcome when it has an `ILogger<Fido2>`; `AddFido2()` passes one whenever logging is
registered. Credential IDs are logged base64url-encoded and truncated to 64 characters.

| Event | Level | When |
| --- | --- | --- |
| 1200 | Information | A credential was registered (credential ID, RP ID, AAGUID, attestation format and type, BE) |
| 1201 | Warning | A registration was rejected (error code and reason) |
| 1202 | Information | An assertion verified (credential ID, sign count, UV, BS) |
| 1203 | Warning | An assertion was rejected (error code and reason) |
| 1204 | Warning | `RecheckMetadataStatusOnAssertion` is on but the assertion had no `StoredAaGuid` |
| 1205 | Error | A ceremony failed with an unexpected exception, e.g. from your own callback (with the exception) |

Rejections are logged without a stack trace, since anyone can trigger them. Cancelled ceremonies are not logged.

## How attestation is checked against metadata

When a registration carries a full attestation and the authenticator's metadata statement lists
`attestationRootCertificates`, the library verifies that the attestation certificate chains to one of them.

- **Any kind of anchor works, on every platform.** MDS allows an anchor to be a root, an intermediate CA, or the
  attestation certificate itself. The chain is built by the platform's engine with partial chains permitted, and
  the attestation certificate is accepted when a declared anchor appears anywhere above it in the verified path.
  This is the same on Windows, Linux and macOS; earlier versions only handled intermediate anchors on Windows.
- **Revocation of the attestation certificate is checked by the library, not by the platform.** If the attestation
  certificate names an HTTP(S) CRL distribution point, the CRL is fetched (once per URL, until its next update),
  its signature is verified against the CA the chain established as the issuer, and the certificate's serial
  number is looked up. A CRL that cannot be fetched, does not verify, or is past its next update fails the
  registration, as does a listed certificate. This needs outbound HTTP from the server to the CA's distribution
  point. The issuing CAs' own status is not checked: the metadata statement vouches for them by naming an anchor.
- **Conformance mode** (`FidoValidationMode.FidoConformance2024`, selected automatically for the conformance
  metadata repository) skips revocation checking, since the conformance tool's certificates name distribution
  points that do not exist.

## Logging

The metadata pipeline reports what it does through `Microsoft.Extensions.Logging`. Every built-in repository and
service takes an optional `ILogger<T>`; the DI registrations pass one in whenever logging is registered, and the
types work without one. The verification hot path does not log -- every failure there surfaces as a
`Fido2VerificationException` with a `Fido2ErrorCode`.

Categories are the type names (`Fido2NetLib.Fido2MetadataServiceRepository` and so on). The events:

| Event | Level | Source | When |
| --- | --- | --- | --- |
| 1000 | Debug | `Fido2MetadataServiceRepository` | Fetching the BLOB (says whether the fetch is conditional on the last ETag) |
| 1001 | Debug | `Fido2MetadataServiceRepository` | The service answered 304; the cached BLOB is reused |
| 1002 | Information | `Fido2MetadataServiceRepository` | The BLOB was downloaded (with its size) |
| 1003 | Warning | `Fido2MetadataServiceRepository` | The service throttled the fetch; a retry is scheduled |
| 1004 | Debug | `Fido2MetadataServiceRepository` | The BLOB signature verified |
| 1005 | Debug | both repositories | The platform did not trust the signing chain; it is checked against the pinned root |
| 1006 | Debug | both repositories | A signing certificate is being checked against its CRL |
| 1007 | Information | `Fido2MetadataServiceRepository` | The BLOB was accepted (number, entry count, next update) |
| 1010 | Warning | `FileSystemMetadataRepository` | The metadata directory does not exist |
| 1011 | Debug | `FileSystemMetadataRepository` | A statement was loaded |
| 1012 | Warning | `FileSystemMetadataRepository` | A statement has no AAGUID and was skipped |
| 1013 | Information | `FileSystemMetadataRepository` | How many statements were loaded |
| 1020 | Information | `ConformanceMetadataRepository` | The conformance tool provisioned its endpoints |
| 1021 | Warning | `ConformanceMetadataRepository` | A BLOB was rejected and skipped (previously silent) |
| 1022 | Information | `ConformanceMetadataRepository` | The accepted BLOBs were combined |
| 1100 | Error | `DistributedCacheMetadataService` | A repository fetch failed |
| 1101 | Warning | `DistributedCacheMetadataService` | The distributed cache held an unreadable BLOB |
| 1102 | Debug | `DistributedCacheMetadataService` | The cached BLOB is current and was used |
| 1103 | Debug | `DistributedCacheMetadataService` | The cached BLOB is due for update; fetching |
| 1104 | Warning | `DistributedCacheMetadataService` | The refresh failed; the due copy is kept |
| 1105 | Information | `DistributedCacheMetadataService` | A BLOB was cached (with its expiry) |
| 1106 | Warning | `DistributedCacheMetadataService` | Nothing is available: the fetch failed and nothing is cached |

Enable `Debug` for `Fido2NetLib` to see every step of a fetch; at `Information` you get one line per download
and one per accepted BLOB, which is enough to confirm the metadata is being refreshed.
