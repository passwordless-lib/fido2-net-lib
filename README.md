# FIDO2 .NET Library (WebAuthn)
A working implementation library + demo for [FIDO2](https://fidoalliance.org/fido2/) and [WebAuthn](https://www.w3.org/TR/webauthn/) using [.NET](https://dotnet.microsoft.com/)  

[![Build status](https://anders.visualstudio.com/Fido2/_apis/build/status/Fido2-CI?label=Build)](https://anders.visualstudio.com/Fido2/_build/latest?definitionId=2)
[![Test Status](https://anders.visualstudio.com/Fido2/_apis/build/status/Fido2%20Tests?branchName=master&label=Tests)](https://anders.visualstudio.com/Fido2/_build/latest?definitionId=3?branchName=master)

### Purpose
To provide a developer friendly and well tested [.NET](https://dotnet.microsoft.com/) [FIDO2 Server](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html) / [WebAuthn relying party](https://www.w3.org/TR/webauthn/#relying-party) library for the easy validation of [registration](https://www.w3.org/TR/webauthn/#usecase-registration) ([attestation](https://www.w3.org/TR/webauthn/#attestation)) and [authentication](https://www.w3.org/TR/webauthn/#usecase-authentication) ([assertion](https://www.w3.org/TR/webauthn/#authentication-assertion)) of [FIDO2](https://fidoalliance.org/fido2/) / [WebAuthn](https://www.w3.org/TR/webauthn/) credentials, in order to increase the adoption of the technology, ultimately defeating phishing attacks.

```Install-Package Fido2 -Version 1.0.0-preview4 ```

### Demo
* **Online example**: https://www.passwordless.dev
* [Code examples](#examples)

## What is FIDO2?
**The passwordless web is coming.**  
[FIDO2](https://fidoalliance.org/fido2/) / [WebAuthn](https://www.w3.org/TR/webauthn/) is a new open authentication standard, supported by [browsers](https://www.w3.org/Consortium/Member/List) and [many large tech companies](https://fidoalliance.org/members/) such as Microsoft, Google etc. The main driver is to allow a user to login without passwords, creating *passwordless flows* or strong MFA for user signup/login on websites. The standard is not limited to web applications with support coming to Active Directory and native apps. The technology builds on public/private keys, allowing authentication to happen without sharing a secret between the user & platform. This brings many benefits, such as easier and safer logins and makes phishing attempts extremely hard.

Read more: 
- [Why it's exciting](http://ideasof.andersaberg.com/development/the-passwordless-web)
- [Medium](https://blog.tokenize.com/fido-2-0-what-is-it-and-why-are-we-excited-31a66df6e113)
- [FIDO Alliance](https://fidoalliance.org/fido2/)
- [Yubico](https://www.yubico.com/2018/08/10-things-youve-been-wondering-about-fido2-webauthn-and-a-passwordless-world/)
- [WebAuthn.Guide](https://webauthn.guide/) from Duo Security
- [WebAuthn.io](https://webauthn.io/) 
- [WebAuthn Awesome](https://github.com/herrjemand/WebauthnAwesome)

## Supported features

- ✅ Attestation API & verification (Register and verify credentials/authenticators)  
- ✅ Assertion API & verification (Authenticate users)
- ✅ 100% pass rate in [conformance testing](#conformance-testing-tool) ([results](https://github.com/abergs/fido2-net-lib/issues/13#issuecomment-457318859))
- ✅ FIDO2 security keys aka roaming authenticators ([spec](https://www.w3.org/TR/webauthn/#roaming-authenticators)), like SoloKeys [Solo](https://github.com/solokeys/solo/blob/master/README.md), Yubico [YubiKey](https://www.yubico.com/products/yubikey-hardware/), and Feitian [BioPass FIDO2](https://www.ftsafe.com/Products/FIDO2))
- ✅ Device embedded authenticators aka platform authenticators ([spec](https://www.w3.org/TR/webauthn/#platform-authenticators)), like [Android Key](https://source.android.com/security/keystore/attestation) and [TPM](https://trustedcomputinggroup.org/resource/trusted-platform-module-2-0-a-brief-introduction/))
- ✅ Backwards compatibility with FIDO U2F authenticators ([spec](https://www.w3.org/TR/#conforming-authenticators-u2f))
- ✅ [Windows Hello](https://docs.microsoft.com/en-us/microsoft-edge/dev-guide/windows-integration/web-authentication) 
- ✅ All currently referenced cryptographic algorithms for FIDO2 Server ([spec](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#other))
- ✅ All current attestation formats: "packed", "tpm", "android-key", "android-safetynet", "fido-u2f", and "none" ([spec](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html))
- ✅ FIDO2 Server attestation validation via FIDO Metadata Service ([spec](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html))
- ✅ WebAuthn extensions ([spec](https://www.w3.org/TR/webauthn/#extensions))
- ✅ Examples & demos
- ✅ Intellisense documentation
- 💤 [Formal documentation](https://github.com/abergs/fido2-net-lib/issues/53)
- 💤 Recommended [usage patterns](https://github.com/abergs/fido2-net-lib/issues/54)

## Configuration

  *Only some options are mentioned here, see the [Configuration](https://github.com/abergs/fido2-net-lib/blob/master/fido2-net-lib/Fido2NetLib.cs) class for all options*

* `fido2:MDSAccessKey` - App Secret / environment variable that holds the FIDO2 MDS AccessKey. *Required when using the default [MetadataService provider](https://fidoalliance.org/mds/).*
* `fido2:MDSCacheDirPath` - App Secret / environment variable that sets the cache path for the MDS. Defaults to "current user's temporary folder"/fido2mdscache. *Optional when using the default [MetadataService provider](https://fidoalliance.org/mds/).*

## Examples

See the [demo controller](Fido2Demo/Controller.cs) for full examples of both [attestation](https://www.w3.org/TR/webauthn/#sctn-attestation) and [assertion](https://www.w3.org/TR/webauthn/#verifying-assertion).

See the [test controller](Fido2Demo/TestController.cs) for examples of how to pass the [conformance tests](#conformance-testing-tool).

See the [Active Directory Store information](https://github.com/abergs/fido2-net-lib/issues/68#issuecomment-451758622) and [example credential store](https://github.com/abergs/fido2-net-lib/blob/ActiveDirectory/fido2-net-lib/ActiveDirectoryStore.cs) for ideas on how to integrate this library with an on-premises Active Directory.

### Create attestation Options

To add FIDO2 credentials to an existing user account, we we perform a attestation process. It starts with returning options to the client.

```csharp
// file: Controller.cs
// 1. Get user from DB by username (in our example, auto create missing users)
var user = DemoStorage.GetOrAddUser(username, () => new User
{
    DisplayName = "Display " + username,
    Name = username,
    Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
});

// 2. Get user existing keys by username
List<PublicKeyCredentialDescriptor> existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

// 3. Create options
var options = _lib.RequestNewCredential(user, existingKeys, AuthenticatorSelection.Default, AttestationConveyancePreference.Parse(attType));

// 4. Temporarily store options, session/in-memory cache/redis/db
HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

// 5. return options to client
return Json(options);
```

### Register credentials

When the client returns a response, we verify and register the credentials.

```csharp
// file: Controller.cs
// 1. get the options we sent the client
var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
var options = CredentialCreateOptions.FromJson(jsonOptions);

// 2. Create callback so that lib can verify credential id is unique to this user
IsCredentialIdUniqueToUserAsyncDelegate callback = async (IsCredentialIdUniqueToUserParams args) =>
{
    List<User> users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId);
    if (users.Count > 0) return false;

    return true;
};

// 2. Verify and make the credentials
var success = await _lib.MakeNewCredentialAsync(attestationResponse, options, callback);

// 3. Store the credentials in db
DemoStorage.AddCredentialToUser(options.User, new StoredCredential
{
    Descriptor = new PublicKeyCredentialDescriptor(success.Result.CredentialId),
    PublicKey = success.Result.PublicKey,
    UserHandle = success.Result.User.Id
});

// 4. return "ok" to the client
return Json(success);
```

### Create Assertion options

When a user wants to log a user in, we do an assertion based on the registered credentials.

First we create the assertion options and return to the client.

```csharp
// file: Controller.cs
// 1. Get user from DB
var user = DemoStorage.GetUser(username);
if (user == null) return NotFound("username was not registered");

// 2. Get registered credentials from database
List<PublicKeyCredentialDescriptor> existingCredentials = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

// 3. Create options
var options = _lib.GetAssertionOptions(
    existingCredentials,
    UserVerificationRequirement.Discouraged
);

// 4. Temporarily store options, session/in-memory cache/redis/db
HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

// 5. Return options to client
return Json(options);
```

### Verify the assertion response
When the client returns a response, we verify it and accepts the login.

```csharp
// 1. Get the assertion options we sent the client
var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
var options = AssertionOptions.FromJson(jsonOptions);

// 2. Get registered credential from database
StoredCredential creds = DemoStorage.GetCredentialById(clientResponse.Id);

// 3. Get credential counter from database
var storedCounter = creds.SignatureCounter;

// 4. Create callback to check if userhandle owns the credentialId
IsUserHandleOwnerOfCredentialIdAsync callback = async (args) =>
{
    List<StoredCredential> storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle);
    return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
};

// 5. Make the assertion
var res = await _lib.MakeAssertionAsync(clientResponse, options, creds.PublicKey, storedCounter, callback);

// 6. Store the updated counter
DemoStorage.UpdateCounter(res.CredentialId, res.Counter);

// 7. return OK to client
return Json(res);
```

## Nuget package

```Install-Package Fido2 -Version 1.0.0-preview ```

https://www.nuget.org/packages/Fido2/

# Contributing

## To run the project locally

Start Fido2Demo (preferably https, expected url https://localhost:44329) and open https://localhost:44329/ in the browser.
You also need to either set the MetadataService to `null` or add the applicationSettings as described below.

The HTML and javascript is copied (and then updated) from WebAuthn.io.

Feedback, issues and pull requests are VERY welcome.

## Build

[![Build status](https://anders.visualstudio.com/Fido2/_apis/build/status/Fido2-CI?label=Build)](https://anders.visualstudio.com/Fido2/_build/latest?definitionId=2)
[![Test Status](https://anders.visualstudio.com/Fido2/_apis/build/status/Fido2%20Tests?branchName=master&label=Tests)](https://anders.visualstudio.com/Fido2/_build/latest?definitionId=3?branchName=master)

All PR's and the master branch is built with Azure Devops.

Scripts to build, pack and publish a nuget package are located in ./scripts/

## Conformance testing tool
To run a suit of test of different verifications and attestation formats, register and download the [FIDO Test tools](https://fidoalliance.org/tool-request-agreement/)

## Other

A complimentary [blog post](http://ideasof.andersaberg.com/development/fido2-net-library) with some lessons learned since starting this library
