# FIDO2 .NET library (WebAuthn)
A working implementation library + demo for fido2 and WebAuthn using .NET 

### Purpose
Provide a developer friendly and well tested .NET server side library for easy validation (attestation & assertion) of WebAuthn/FIDO2 credentials to increase the adoption of the technology, ultimately defeating phishing attacks.

```Install-Package Fido2 -Version 1.0.0-preview ```

### Demo
* **Online example**: https://fido2.azurewebsites.net/
* [Code examples](#examples)

**To run the demo locally**: Start Fido2Demo (preferably https, expected url https://localhost:44329) and open https://localhost:44329/ in the browser.
You also need to either set the MetadataService to `null` or add the applicationSettings as described below.

In order to utilize the metadata provided from FIDO Alliance Metadata Service you must register for an access token (https://fidoalliance.org/mds/).  Set the `fido2:MDSAccessKey` app secret value to your access token, and the `fido2:MDSCacheDirPath` app secret value to a local directory to cache metadata. See https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets for more information on app secret usage.

The HTML and javascript is copied (and then updated) from WebAuthn.io.

Feedback, issues and pull requests are VERY welcome.


## Supported features

- ✅ Attestation API & verification (Register and verify credentials/authenticators)  
- ✅ Assertion API & verification (Authenticate users)
- ✅ 100% success rate in conformance testing ([results](https://github.com/abergs/fido2-net-lib/issues/13))
- ✅ Fido 2 Security Keys  
- ✅ Backwards compatibility with Fido-u2f.  
- ✅ Windows Hello support  
- ✅ ES256 Public Key format  
- ✅ "none", "fido-u2f", "android-key", "android-safetynet", "tpm" & "packed" attestation formats
- ✅ Examples & demo's
- ✅ Intellisense documentation  
- 💤 [Formal documentation](https://github.com/abergs/fido2-net-lib/issues/53)
- 💤 Recommended [usage patterns](https://github.com/abergs/fido2-net-lib/issues/54)
- ❌ [Extensions](https://github.com/abergs/fido2-net-lib/issues/55)


## Configuration

  *Only some options are mention here, see the [Configuration](https://github.com/abergs/fido2-net-lib/blob/master/fido2-net-lib/Fido2NetLib.cs) class for all options*

* `fido2:MDSAccessKey` - App Secret / environment variable that holds the FIDO2 MDS AccessKey. *Required when using the default [MetadataService provider](https://fidoalliance.org/mds/).*
* `fido2:MDSCacheDirPath` - App Secret / environment variable that sets the cache path for the MDS. *Required when using the default [MetadataService provider](https://fidoalliance.org/mds/).*

## Examples

Please see the [demo controller](https://github.com/abergs/fido2-net-lib/blob/master/Fido2Demo/Controller.cs) for full examples of both Attestation & Assertion.

### Create attestation Options

To add fido2 credentials to an existing user account, we we perform a attestation process. It starts with returning options to the client.

```
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

```
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

```
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

```
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

## Conformance testing tool
To run a suit of test of different verifications and attestation formats, register and download the [FIDO Test tools](https://fidoalliance.org/test-tool-access-request/)

## Other

A complimentary [blog post](http://ideasof.andersaberg.com/development/fido2-net-library) with some lessons learned since starting this library
