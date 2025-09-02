# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the FIDO2 .NET Library (WebAuthn) - a working implementation library for FIDO2 and WebAuthn using .NET. It provides a developer-friendly and well-tested .NET FIDO2 Server/WebAuthn relying party library for validation of registration (attestation) and authentication (assertion) of FIDO2/WebAuthn credentials.

## Architecture

The solution is organized into several key projects:

### Core Library Projects

- **Src/Fido2.Models** - Core data models and DTOs for FIDO2/WebAuthn, shared across all projects
- **Src/Fido2** - Main FIDO2 library with attestation/assertion verification logic, cryptographic operations, and metadata service integration
- **Src/Fido2.AspNet** - ASP.NET Core integration helpers and extensions
- **Src/Fido2.Ctap2** - CTAP2 protocol implementation for FIDO2 authenticators
- **Src/Fido2.BlazorWebAssembly** - Blazor WebAssembly-specific components and helpers
- **Src/Fido2.Development** - Development and testing utilities

### Demo/Example Projects

- **Demo** - ASP.NET Core demo application showing FIDO2 registration and authentication flows
- **BlazorWasmDemo** - Blazor WebAssembly demo application (Client/Server projects)

### Test Projects

- **Tests/Fido2.Tests** - Main unit test suite using xUnit
- **Tests/Fido2.Ctap2.Tests** - Tests for CTAP2 functionality

## Development Commands

### Building

```bash
# Build entire solution
dotnet build fido2-net-lib.sln --configuration Release

# Build specific project
dotnet build Demo/Demo.csproj --configuration Release
```

### Testing

```bash
# Run all tests
dotnet test Tests/Fido2.Tests/Fido2.Tests.csproj

# Run tests with coverage
dotnet test Tests/Fido2.Tests/Fido2.Tests.csproj --collect:"XPlat Code Coverage"
```

### Code Formatting

```bash
# Check formatting
dotnet format --verify-no-changes --no-restore

# Apply formatting
dotnet format
```

### Running Demo Applications

```bash
# Run ASP.NET Core demo (requires HTTPS, expected at https://localhost:5001)
dotnet run --project Demo/Demo.csproj

# Run Blazor WebAssembly demo
dotnet run --project BlazorWasmDemo/Server/BlazorWasmDemo.Server.csproj
```

## Configuration

### Key Configuration Files

- **Directory.Build.props** - Root build configuration with package metadata and global settings
- **Src/Directory.Build.props** - Source-specific build settings
- **azure-pipelines.yml** - CI/CD pipeline configuration

### Important Settings

- Target Framework: .NET 8.0 (configured via `SupportedTargetFrameworks`)
- Language Version: C# 12
- Nullable reference types enabled
- ImplicitUsings enabled globally
- TreatWarningsAsErrors enabled

## Code Style Guidelines

- Use 4 spaces for indentation (no tabs)
- Use `_camelCase` for private fields
- Always specify member visibility explicitly
- Use `var` keyword when type is obvious
- Use primitive type keywords (`int` vs `Int32`)
- Document public APIs with XmlDoc comments
- Avoid `this.` unless necessary
- Use expression-bodied members when appropriate for readability

## Key Dependencies

- **NSec.Cryptography** - Cryptographic operations
- **System.Formats.Cbor** - CBOR encoding/decoding
- **Microsoft.IdentityModel.JsonWebTokens** - JWT token handling
- **Microsoft.Extensions.Http** - HTTP client factory

## Testing Framework

- **xUnit** - Primary test framework
- **Moq** - Mocking framework
- **coverlet.collector** - Code coverage collection

## Important Notes

- The project passes 100% of FIDO Alliance conformance tests
- Supports all current attestation formats: packed, tpm, android-key, android-safetynet, fido-u2f, apple, apple-appattest, and none
- Includes FIDO Metadata Service V3 validation support
- Cross-platform compatible (Windows, macOS, Linux)
- Root namespace is `Fido2NetLib` for all projects
