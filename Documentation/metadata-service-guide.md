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
