# FIDO2 .NET library (WebAuthn)

[Readme](https://github.com/passwordless-lib/fido2-net-lib/blob/master/README.md)

2020-03-24 1.1.0
- Refactored FIDO2 model
- Finish removing cng for cross platform to work. Also add MDSCacheDirPath that got missed in #132.  Passes 172/172 conformance tests on tools build 1.2.1.
- Adding the MDS configurations to the Fido2Configuration. (#134)
- Adds xml comment documentation (#122)
- Sign the actual data, not a hash of the data (#128)
- Conformance tool recently changed the way EdDSA signatures are verified.  This fix passes the test in v1.1.6.

2019-07-31 1.0.1
- initial release FIDO2 .NET library (WebAuthn)
