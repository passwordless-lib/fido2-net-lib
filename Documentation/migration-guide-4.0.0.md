# Upgrade Guide: FIDO2 .NET Library v3.0.1 → v4.0.0

This guide helps you migrate your code from FIDO2 .NET Library version 3.0.1 to version 4.0.0. Version 4.0.0 introduces significant breaking changes primarily focused on improving API ergonomics through parameter wrapper classes and enhanced extension support.

## Overview of Breaking Changes

### ✅ What Remains the Same

- Core FIDO2/WebAuthn functionality and security guarantees
- Configuration and setup patterns
- Callback delegate signatures
- Most model objects and their properties

### ⚠️ What Changed (Breaking)

- **API Method Signatures**: All main API methods now use parameter wrapper classes
- **Return Types**: Some return types have been renamed/restructured
- **Extension Support**: Significantly expanded WebAuthn extensions
- **Framework Target**: Now targets .NET 8.0
- **Nullable Reference Types**: Comprehensive nullable annotations

## Migration Steps

### 1. Update Target Framework

Update your project to target .NET 8.0:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>
```

### 2. Update Package References

```xml
<PackageReference Include="Fido2" Version="4.0.0" />
<PackageReference Include="Fido2.AspNet" Version="4.0.0" />
```

### 3. Update API Method Calls

#### RequestNewCredential Method

**Before (v3.0.1):**

```csharp
// Simple overload
var options = fido2.RequestNewCredential(
    user,
    excludeCredentials,
    extensions);

// Full overload
var options = fido2.RequestNewCredential(
    user,
    excludeCredentials,
    authenticatorSelection,
    attestationPreference,
    extensions);
```

**After (v4.0.0):**

```csharp
var options = fido2.RequestNewCredential(new RequestNewCredentialParams
{
    User = user,
    ExcludeCredentials = excludeCredentials,
    AuthenticatorSelection = authenticatorSelection, // Optional, has default
    AttestationPreference = attestationPreference,   // Optional, has default
    Extensions = extensions,                         // Optional
    PubKeyCredParams = PubKeyCredParam.Defaults     // Optional, has default
});
```

#### MakeNewCredentialAsync Method

**Before (v3.0.1):**

```csharp
var result = await fido2.MakeNewCredentialAsync(
    attestationResponse,
    originalOptions,
    isCredentialIdUniqueToUser,
    requestTokenBindingId,      // Deprecated parameter
    cancellationToken);
```

**After (v4.0.0):**

```csharp
var result = await fido2.MakeNewCredentialAsync(
    new MakeNewCredentialParams
    {
        AttestationResponse = attestationResponse,
        OriginalOptions = originalOptions,
        IsCredentialIdUniqueToUserCallback = isCredentialIdUniqueToUser
        // RequestTokenBindingId removed (was deprecated)
    },
    cancellationToken);
```

#### GetAssertionOptions Method

**Before (v3.0.1):**

```csharp
var options = fido2.GetAssertionOptions(
    allowedCredentials,
    userVerification,
    extensions);
```

**After (v4.0.0):**

```csharp
var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
{
    AllowedCredentials = allowedCredentials,  // Now IReadOnlyList
    UserVerification = userVerification,
    Extensions = extensions
});
```

#### MakeAssertionAsync Method

**Before (v3.0.1):**

```csharp
var result = await fido2.MakeAssertionAsync(
    assertionResponse,
    originalOptions,
    storedPublicKey,
    storedSignatureCounter,
    isUserHandleOwnerOfCredentialIdCallback,
    requestTokenBindingId,      // Deprecated parameter
    cancellationToken);
```

**After (v4.0.0):**

```csharp
var result = await fido2.MakeAssertionAsync(
    new MakeAssertionParams
    {
        AssertionResponse = assertionResponse,
        OriginalOptions = originalOptions,
        StoredPublicKey = storedPublicKey,
        StoredSignatureCounter = storedSignatureCounter,
        IsUserHandleOwnerOfCredentialIdCallback = isUserHandleOwnerOfCredentialIdCallback
        // RequestTokenBindingId removed (was deprecated)
    },
    cancellationToken);
```

### 4. Update Return Type Handling

#### MakeNewCredentialAsync Return Type

**Before (v3.0.1):**

```csharp
Fido2.CredentialMakeResult result = await fido2.MakeNewCredentialAsync(...);
// or
AttestationVerificationSuccess result = await fido2.MakeNewCredentialAsync(...);
```

**After (v4.0.0):**

```csharp
RegisteredPublicKeyCredential result = await fido2.MakeNewCredentialAsync(...);

// Access properties (most remain the same)
var credentialId = result.Id;           // Previously CredentialId
var publicKey = result.PublicKey;
var user = result.User;
var counter = result.Counter;
```

#### MakeAssertionAsync Return Type

**Before (v3.0.1):**

```csharp
AssertionVerificationResult result = await fido2.MakeAssertionAsync(...);
```

**After (v4.0.0):**

```csharp
VerifyAssertionResult result = await fido2.MakeAssertionAsync(...);
```

### 5. Update Collection Types

Several APIs now use `IReadOnlyList<T>` instead of `IEnumerable<T>` or `List<T>`:

**Before (v3.0.1):**

```csharp
List<PublicKeyCredentialDescriptor> excludeCredentials = ...;
IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials = ...;
```

**After (v4.0.0):**

```csharp
// These work fine as IReadOnlyList is covariant
IReadOnlyList<PublicKeyCredentialDescriptor> excludeCredentials = ...;
IReadOnlyList<PublicKeyCredentialDescriptor> allowedCredentials = ...;

// Or keep existing types - they're compatible
List<PublicKeyCredentialDescriptor> excludeCredentials = ...;  // Still works
```

### 6. Enhanced Extensions Support

Version 4.0.0 significantly expands WebAuthn extensions support. Update your extension usage:

**New Extensions Available:**

```csharp
var extensions = new AuthenticationExtensionsClientInputs
{
    // Existing extensions
    Extensions = true,

    // New in v4.0.0
    CredProps = true,
    PRF = new AuthenticationExtensionsPRFInputs { ... },
    LargeBlob = new AuthenticationExtensionsLargeBlobInputs { ... },
    CredentialProtectionPolicy = CredentialProtectionPolicy.UserVerificationRequired,
    EnforceCredentialProtectionPolicy = true
};
```

### 7. AttestationConveyancePreference Update

A new `Enterprise` value was added:

```csharp
// New option available
var attestationPreference = AttestationConveyancePreference.Enterprise;
```

## Complete Migration Example

Here's a complete before/after example showing a typical registration flow:

### Before (v3.0.1)

```csharp
public class Fido2Service
{
    private readonly IFido2 _fido2;

    public CredentialCreateOptions BeginRegistration(Fido2User user, List<PublicKeyCredentialDescriptor> existingKeys)
    {
        return _fido2.RequestNewCredential(
            user,
            existingKeys,
            AuthenticatorSelection.Default,
            AttestationConveyancePreference.Direct,
            new AuthenticationExtensionsClientInputs { Extensions = true });
    }

    public async Task<AttestationVerificationSuccess> CompleteRegistrationAsync(
        AuthenticatorAttestationRawResponse response,
        CredentialCreateOptions options,
        IsCredentialIdUniqueToUserAsyncDelegate callback)
    {
        return await _fido2.MakeNewCredentialAsync(response, options, callback);
    }

    public AssertionOptions BeginAuthentication(List<PublicKeyCredentialDescriptor> allowedCredentials)
    {
        return _fido2.GetAssertionOptions(
            allowedCredentials,
            UserVerificationRequirement.Preferred,
            new AuthenticationExtensionsClientInputs { Extensions = true });
    }

    public async Task<AssertionVerificationResult> CompleteAuthenticationAsync(
        AuthenticatorAssertionRawResponse response,
        AssertionOptions options,
        byte[] publicKey,
        uint counter,
        IsUserHandleOwnerOfCredentialIdAsync callback)
    {
        return await _fido2.MakeAssertionAsync(response, options, publicKey, counter, callback);
    }
}
```

### After (v4.0.0)

```csharp
public class Fido2Service
{
    private readonly IFido2 _fido2;

    public CredentialCreateOptions BeginRegistration(Fido2User user, IReadOnlyList<PublicKeyCredentialDescriptor> existingKeys)
    {
        return _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = user,
            ExcludeCredentials = existingKeys,
            AuthenticatorSelection = AuthenticatorSelection.Default,
            AttestationPreference = AttestationConveyancePreference.Direct,
            Extensions = new AuthenticationExtensionsClientInputs
            {
                Extensions = true,
                CredProps = true  // New extension support
            }
        });
    }

    public async Task<RegisteredPublicKeyCredential> CompleteRegistrationAsync(
        AuthenticatorAttestationRawResponse response,
        CredentialCreateOptions options,
        IsCredentialIdUniqueToUserAsyncDelegate callback)
    {
        return await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = response,
            OriginalOptions = options,
            IsCredentialIdUniqueToUserCallback = callback
        });
    }

    public AssertionOptions BeginAuthentication(IReadOnlyList<PublicKeyCredentialDescriptor> allowedCredentials)
    {
        return _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowedCredentials,
            UserVerification = UserVerificationRequirement.Preferred,
            Extensions = new AuthenticationExtensionsClientInputs { Extensions = true }
        });
    }

    public async Task<VerifyAssertionResult> CompleteAuthenticationAsync(
        AuthenticatorAssertionRawResponse response,
        AssertionOptions options,
        byte[] publicKey,
        uint counter,
        IsUserHandleOwnerOfCredentialIdAsync callback)
    {
        return await _fido2.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = publicKey,
            StoredSignatureCounter = counter,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        });
    }
}
```

## Common Migration Issues and Solutions

### Issue 1: Compiler Errors on Method Calls

**Error:** `No overload for method 'RequestNewCredential' takes 3 arguments`

**Solution:** Wrap parameters in the appropriate parameter class:

```csharp
// Change this:
fido2.RequestNewCredential(user, excludeCredentials, extensions);

// To this:
fido2.RequestNewCredential(new RequestNewCredentialParams
{
    User = user,
    ExcludeCredentials = excludeCredentials,
    Extensions = extensions
});
```

### Issue 2: Return Type Casting Errors

**Error:** `Cannot implicitly convert type 'RegisteredPublicKeyCredential' to 'AttestationVerificationSuccess'`

**Solution:** Update variable types:

```csharp
// Change this:
AttestationVerificationSuccess result = await fido2.MakeNewCredentialAsync(...);

// To this:
RegisteredPublicKeyCredential result = await fido2.MakeNewCredentialAsync(...);
```

### Issue 3: Required Property Initialization

**Error:** `Required member 'RequestNewCredentialParams.User' must be set in the object initializer`

**Solution:** Ensure all required properties are set:

```csharp
new RequestNewCredentialParams
{
    User = user,  // Required
    // Other optional properties...
}
```
