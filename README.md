# Passkeys - FIDO2 .NET Library (WebAuthn)

A fully working and battle tested library for passkeys ([FIDO2](https://fidoalliance.org/fido2/) and [WebAuthn](https://www.w3.org/TR/webauthn/)) on [.NET](https://dotnet.microsoft.com/)

[![codecov](https://codecov.io/gh/passwordless-lib/fido2-net-lib/branch/main/graph/badge.svg)](https://codecov.io/gh/passwordless-lib/fido2-net-lib)
[![Financial Contributors on Open Collective](https://opencollective.com/passwordless/all/badge.svg?label=financial+contributors)](https://opencollective.com/passwordless)
[![NuGet Status](http://img.shields.io/nuget/v/Fido2.svg?style=flat-square)](https://www.nuget.org/packages/Fido2/)

[Releases & Change log](https://github.com/passwordless-lib/fido2-net-lib/releases)

> ### 💡 Bitwarden Passwordless API
>
> The quickest way to get started with FIDO2 and WebAuthn is with the [Bitwarden Passwordless API](https://passwordless.dev?gh). It's free up to 10k users and a faster way to start using passkeys on your website or mobile app.
>
> Bitwarden Passwordless.dev supports .NET Framework as well as the latest .net 8+.
>
> [Get started with passwordless.dev](https://docs.passwordless.dev/guide/get-started.html)

### Purpose

<img align="right" width="100px" src="https://user-images.githubusercontent.com/357283/188737052-4735ba0a-08b5-47e8-9b2c-02c8829d2413.png" />
Our purpose is to enable passwordless sign in for all .NET apps (asp, core, native).

To provide a developer friendly and well tested [.NET](https://dotnet.microsoft.com/) [FIDO2 Server](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html) / [WebAuthn relying party](https://www.w3.org/TR/webauthn/#relying-party) library for the easy validation of [registration](https://www.w3.org/TR/webauthn/#usecase-registration) ([attestation](https://www.w3.org/TR/webauthn/#attestation)) and [authentication](https://www.w3.org/TR/webauthn/#usecase-authentication) ([assertion](https://www.w3.org/TR/webauthn/#authentication-assertion)) of [FIDO2](https://fidoalliance.org/fido2/) / [WebAuthn](https://www.w3.org/TR/webauthn/) credentials, in order to increase the adoption of the technology, ultimately defeating phishing attacks.

This project is part of the [.NET foundation](https://dotnetfoundation.org)

## Installation

**Requirements**: .NET 8.0 or later

```bash
dotnet add package Fido2
```

To use the ASP.NET Core helpers:

```bash
dotnet add package Fido2.AspNet
```

For Blazor WebAssembly support:

```bash
dotnet add package Fido2.BlazorWebAssembly
```

> **⚠️ Breaking Changes**: If upgrading from v3.x, see the [Upgrade Guide](upgrade-guide.md) for migration instructions.

### Demo

- **Library website**: https://fido2-net-lib.passwordless.dev
- [Code examples](#examples)

## What is FIDO2?

**The passwordless web is here.**
[FIDO2](https://fidoalliance.org/fido2/) / [WebAuthn](https://www.w3.org/TR/webauthn/) is a modern, stable and open authentication standard, supported by [browsers](https://www.w3.org/Consortium/Member/List) and [many large tech companies](https://fidoalliance.org/members/) such as Microsoft, Google etc. The main driver is to allow a user to login without passwords, creating _passwordless flows_ or strong MFA for user signup/login on websites. The standard is not limited to web applications with support coming to native apps. The technology builds on public/private keys, allowing authentication to happen without sharing a secret between the user & website. This brings many benefits, such as easier and safer logins and makes phishing attempts extremely hard.

Read more:

- [Why it's exciting](http://ideasof.andersaberg.com/development/the-passwordless-web)
- [Medium](https://medium.com/tokenring/fido-2-0-what-is-it-and-why-are-we-excited-31a66df6e113)
- [FIDO Alliance](https://fidoalliance.org/fido2/)
- [Yubico](https://www.yubico.com/2018/08/10-things-youve-been-wondering-about-fido2-webauthn-and-a-passwordless-world/)
- [WebAuthn.Guide](https://webauthn.guide/) from Duo Security
- [WebAuthn.io](https://webauthn.io/)
- [WebAuthn Awesome](https://github.com/herrjemand/WebauthnAwesome)

## Supported features

- ✅ Attestation API & verification (Register and verify credentials/authenticators)
- ✅ Assertion API & verification (Authenticate users)
- ✅ 100% pass rate in [conformance testing](#conformance-testing-tool) ([results](https://github.com/passwordless-lib/fido2-net-lib/issues/13#issuecomment-457318859))
- ✅ FIDO2 security keys aka roaming authenticators ([spec](https://www.w3.org/TR/webauthn/#roaming-authenticators)), like SoloKeys [Solo](https://github.com/solokeys/solo/blob/master/README.md), Yubico [YubiKey](https://www.yubico.com/products/yubikey-hardware/), and Feitian [BioPass FIDO2](https://www.ftsafe.com/Products/FIDO2))
- ✅ Device embedded authenticators aka platform authenticators ([spec](https://www.w3.org/TR/webauthn/#platform-authenticators)), like [Android Key](https://source.android.com/security/keystore/attestation) and [TPM](https://trustedcomputinggroup.org/resource/trusted-platform-module-2-0-a-brief-introduction/))
- ✅ Backwards compatibility with FIDO U2F authenticators ([spec](https://www.w3.org/TR/#conforming-authenticators-u2f))
- ✅ [Windows Hello](https://docs.microsoft.com/en-us/microsoft-edge/dev-guide/windows-integration/web-authentication)
- ✅ [Face ID and Touch ID for the Web](https://webkit.org/blog/11312/meet-face-id-and-touch-id-for-the-web/) (aka "Apple Hello")
- ✅ All currently referenced cryptographic algorithms for FIDO2 Server ([spec](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#other))
- ✅ All current attestation formats: "packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "apple", "apple-appattest", and "none" ([spec](https://www.iana.org/assignments/webauthn/webauthn.xhtml))
- ✅ FIDO2 Server attestation validation via FIDO Metadata Service V3 ([spec](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html))
- ✅ WebAuthn extensions ([spec](https://www.w3.org/TR/webauthn/#extensions)) including PRF, Large Blob, Credential Protection
- ✅ Blazor WebAssembly support for client-side applications
- ✅ Examples & demos (ASP.NET Core and Blazor WebAssembly)
- ✅ Intellisense documentation

## Configuration

_Only some options are mentioned here, see the [Configuration](https://github.com/passwordless-lib/fido2-net-lib/blob/master/Src/Fido2.Models/Fido2Configuration.cs) class for all options_

- `fido2:MDSCacheDirPath` - App Secret / environment variable that sets the cache path for the MDS. Defaults to "current user's temporary folder"/fido2mdscache. _Optional when using the default [MetadataService provider](https://fidoalliance.org/mds/)._

## Quick Start

### 1. Configure Services (ASP.NET Core)

```csharp
services.AddFido2(options =>
{
    options.ServerDomain = "example.com";
    options.ServerName = "Example App";
    options.Origins = new HashSet<string> { "https://example.com" };
});
```

### 2. Inject IFido2 Service

```csharp
public class AuthController : Controller
{
    private readonly IFido2 _fido2;

    public AuthController(IFido2 fido2)
    {
        _fido2 = fido2;
    }
}
```

## Examples

- **[ASP.NET Core Demo](Demo/)** - Complete implementation with registration and authentication
- **[Blazor WebAssembly Demo](BlazorWasmDemo/)** - Client-side Blazor example
- **[Test Controller](Demo/TestController.cs)** - Conformance test examples

For integration patterns, see:

- [Active Directory Store information](https://github.com/passwordless-lib/fido2-net-lib/issues/68#issuecomment-451758622)
- [Example credential store](https://github.com/passwordless-lib/fido2-net-lib/blob/ActiveDirectory/fido2-net-lib/ActiveDirectoryStore.cs)

### Create Attestation Options

To add FIDO2 credentials to an existing user account, start by creating options for the client.

```csharp
// 1. Get user from DB by username (in our example, auto create missing users)
var user = DemoStorage.GetOrAddUser(username, () => new User
{
    DisplayName = "Display " + username,
    Name = username,
    Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
});

// 2. Get user existing keys by username
var existingKeys = DemoStorage.GetCredentialsByUser(user)
    .Select(c => c.Descriptor)
    .ToList();

// 3. Create options using new parameter wrapper
var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
{
    User = user,
    ExcludeCredentials = existingKeys,
    AuthenticatorSelection = AuthenticatorSelection.Default,
    AttestationPreference = AttestationConveyancePreference.Parse(attType),
    Extensions = new AuthenticationExtensionsClientInputs
    {
        CredProps = true  // Enable credential properties extension
    }
});

// 4. Temporarily store options, session/in-memory cache/redis/db
HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

// 5. Return options to client
return Json(options);
```

### Register Credentials

When the client returns a response, verify and register the credentials.

```csharp
// 1. Get the options we sent the client and remove from storage
var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
HttpContext.Session.Remove("fido2.attestationOptions");
var options = CredentialCreateOptions.FromJson(jsonOptions);

// 2. Create callback so that lib can verify credential id is unique to this user
IsCredentialIdUniqueToUserAsyncDelegate callback = async (IsCredentialIdUniqueToUserParams args) =>
{
    var users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId);
    return users.Count == 0; // Return true if credential ID is unique
};

// 3. Verify and make the credentials using new parameter wrapper
var result = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
{
    AttestationResponse = attestationResponse,
    OriginalOptions = options,
    IsCredentialIdUniqueToUserCallback = callback
});

// 4. Store the credentials in database
DemoStorage.AddCredentialToUser(options.User, new StoredCredential
{
    Descriptor = new PublicKeyCredentialDescriptor(result.Id),
    PublicKey = result.PublicKey,
    UserHandle = result.User.Id
});

// 5. Return success to client
return Json(result);
```

### Create Assertion Options

For user authentication, create assertion options based on registered credentials.

```csharp
// 1. Get user from DB
var user = DemoStorage.GetUser(username);
if (user == null) return NotFound("Username was not registered");

// 2. Get registered credentials from database
var existingCredentials = DemoStorage.GetCredentialsByUser(user)
    .Select(c => c.Descriptor)
    .ToList();

// 3. Create options using new parameter wrapper
var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
{
    AllowedCredentials = existingCredentials,
    UserVerification = UserVerificationRequirement.Preferred,
    Extensions = new AuthenticationExtensionsClientInputs
    {
        Extensions = true
    }
});

// 4. Temporarily store options, session/in-memory cache/redis/db
HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

// 5. Return options to client
return Json(options);
```

### Verify the Assertion Response

When the client returns a response, verify it and accept the login.

```csharp
// 1. Get the assertion options we sent the client and remove from storage
var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
HttpContext.Session.Remove("fido2.assertionOptions");
var options = AssertionOptions.FromJson(jsonOptions);

// 2. Get registered credential from database
var creds = DemoStorage.GetCredentialById(clientResponse.Id);

// 3. Create callback to check if userhandle owns the credentialId
IsUserHandleOwnerOfCredentialIdAsync callback = async (args) =>
{
    var storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle);
    return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
};

// 4. Make the assertion using new parameter wrapper
var result = await _fido2.MakeAssertionAsync(new MakeAssertionParams
{
    AssertionResponse = clientResponse,
    OriginalOptions = options,
    StoredPublicKey = creds.PublicKey,
    StoredSignatureCounter = creds.SignatureCounter,
    IsUserHandleOwnerOfCredentialIdCallback = callback
});

// 5. Store the updated counter
DemoStorage.UpdateCounter(result.CredentialId, result.Counter);

// 6. Return success to client
return Json(result);
```

## Nuget package

https://www.nuget.org/packages/Fido2/ and https://www.nuget.org/packages/Fido2.Models/

# Contributing

See [Contributing](CONTRIBUTING.md) for information about contributing to the project.

This project has adopted the code of conduct defined by the Contributor Covenant to clarify expected behavior in our community.
For more information see the [.NET Foundation Code of Conduct](https://dotnetfoundation.org/code-of-conduct).

For security and penetration testing, please see our [Vulnerability Disclosure Program](./VDP.md)

## Contributors

### Code Contributors

This project exists thanks to all the people who contribute. [[Contribute](https://github.com/passwordless-lib/fido2-net-lib/tree/master#contributing)].
<a href="https://github.com/passwordless-lib/fido2-net-lib/graphs/contributors"><img src="https://opencollective.com/passwordless/contributors.svg?width=890&button=false" /></a>

### Financial Contributors

Become a financial contributor and help us sustain our community. [[Contribute](https://opencollective.com/passwordless/contribute)]

#### Individuals

<a href="https://opencollective.com/passwordless"><img src="https://opencollective.com/passwordless/individuals.svg?width=890"></a>

#### Organizations

Support this project with your organization. Your logo will show up here with a link to your website. [[Contribute](https://opencollective.com/passwordless/contribute)]

<a href="https://opencollective.com/passwordless/organization/0/website"><img src="https://opencollective.com/passwordless/organization/0/avatar.svg"></a>
<a href="https://opencollective.com/passwordless/organization/1/website"><img src="https://opencollective.com/passwordless/organization/1/avatar.svg"></a>
<a href="https://opencollective.com/passwordless/organization/2/website"><img src="https://opencollective.com/passwordless/organization/2/avatar.svg"></a>
<a href="https://opencollective.com/passwordless/organization/3/website"><img src="https://opencollective.com/passwordless/organization/3/avatar.svg"></a>
<a href="https://opencollective.com/passwordless/organization/4/website"><img src="https://opencollective.com/passwordless/organization/4/avatar.svg"></a>
<a href="https://opencollective.com/passwordless/organization/5/website"><img src="https://opencollective.com/passwordless/organization/5/avatar.svg"></a>
<a href="https://opencollective.com/passwordless/organization/6/website"><img src="https://opencollective.com/passwordless/organization/6/avatar.svg"></a>
<a href="https://opencollective.com/passwordless/organization/7/website"><img src="https://opencollective.com/passwordless/organization/7/avatar.svg"></a>
<a href="https://opencollective.com/passwordless/organization/8/website"><img src="https://opencollective.com/passwordless/organization/8/avatar.svg"></a>
<a href="https://opencollective.com/passwordless/organization/9/website"><img src="https://opencollective.com/passwordless/organization/9/avatar.svg"></a>

### .NET Foundation

This project is supported by the [.NET Foundation](https://dotnetfoundation.org).
