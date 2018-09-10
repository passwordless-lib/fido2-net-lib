# FIDO2 .NET library (WebAuthn)
A working (maybe still proof of concept) implementation library + demo for fido2 and WebAuthn using .NET (Work in progress)

**Purpose**: Provide a developer friendly and well tested .NET server side library for easy validation (attestation & assertion) of WebAuthn/FIDO2 credentials to increase the adoption of the technology, ultimately defeating phishing attacks.

Demo: https://fido2.azurewebsites.net/

To run the demo locally: Start Fido2Demo (SSL, expected url https://localhost:44329) and open https://localhost:44329/ in the browser.

If you want to have a look at the code, the most interesting is these files for now:

* [Controller.cs](https://github.com/abergs/fido2-net-lib/blob/master/Fido2Demo/Controller.cs)
* [Fido2NetLib.cs](https://github.com/abergs/fido2-net-lib/blob/master/fido2-net-lib/Fido2NetLib.cs)
* [AuthenticatorAttestationResponse.cs](https://github.com/abergs/fido2-net-lib/blob/master/fido2-net-lib/AuthenticatorAttestationResponse.cs)

The HTML and javascript is copied (more or less as-is) from WebAuthn.io.

Feedback, issues and pull requests are VERY welcome.


## Supported features

- ✅ Attestation API & verification (Register and verify credentials/authenticators)  
- ✅ Assertion API & verification (Authenticate users)  
- ✅ Fido 2 Security Keys  
- ✅ Backwards compatibility with Fido-u2f.  
- ✅ Windows Hello support  
- ✅ ES256 Public Key format  
- ✅ "none", "fido-u2f", "android-safetynet", "TPM" & "packed" attestation formats  
- ❌ "android-key" attestation formats mostly done, still in progress
- ❌ Extensions  
- ✅ Examples & demo's
- ✅ Intellisense documentation  
- ❌ Formal documentation
- ❌ Recommended usage patterns

## Conformance testing tool
To run a suit of test of different verifications and attestation formats, register and download the [FIDO Test tools](https://fidoalliance.org/test-tool-access-request/)

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

Coming when lib has matured. (https://www.nuget.org/packages/Fido2/)

## Other

A complimentary [blog post](http://ideasof.andersaberg.com/development/fido2-net-library) with some lessons learned since starting this library
