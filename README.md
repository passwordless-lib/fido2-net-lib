# FIDO2 .NET library (WebAuthn)
A working (maybe still proof of concept) implementation library + demo for fido2 and WebAuthn using .NET (Work in progress)

Demo: https://fido2.azurewebsites.net/

To run the demo locally: Start Fido2Demo (SSL, expected url https://localhost:44329) and open https://localhost:44329/ in the browser.

If you want to have a look at the code, the most interesting is these files for now:

* [Controller.cs](https://github.com/abergs/fido2-net-lib/blob/master/Fido2Demo/Controller.cs)
* [Fido2NetLib.cs](https://github.com/abergs/fido2-net-lib/blob/master/fido2-net-lib/Fido2NetLib.cs)
* [AuthenticatorAttestationResponse.cs](https://github.com/abergs/fido2-net-lib/blob/master/fido2-net-lib/AuthenticatorAttestationResponse.cs)

The HTML and javascript is copied (more or less as-is) from WebAuthn.io.

Feedback, issues and pull requests are VERY welcome.


## Supported features

✅ Attestation API & verification (Register and verify credentials/authenticators)  
✅ Assertment API & verification (Authenticate users)  
✅ Fido 2 Security Keys  
✅ Backwards compatability with Fido-u2f.  
✅ Windows Hello support  
✅ ES256 Public Key format  
✅ "none", "fido-u2f" & "packed" attestation formats  
❌ "tpm", "android-key", "android-safetynet"  
❌ Extensions  
✅ Intellisense documentation  
❌ Formal documentation & examples

## Conformance testing tool
To run a suit of test of different verifcations and attestation formats, register and download the [FIDO Test tools](https://fidoalliance.org/test-tool-access-request/)

## Examples

Coming soon

## Nuget package

Coming when lib has matured.
