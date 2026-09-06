using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test.Attestation;

public class None : Fido2Tests.Attestation
{
    public None()
    {
        _attestationObject = new CborMap { { "fmt", "none" } };
    }

    [Fact]
    public async Task TestNone()
    {
        foreach (var (keyType, alg, crv) in Fido2Tests._validCOSEParameters)
        {
            // P256K is not supported on macOS
            if (OperatingSystem.IsMacOS() && crv is COSE.EllipticCurve.P256K)
                continue;

            _attestationObject.Add("attStmt", new CborMap());
            _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey((keyType, alg, crv));


            var credential = await MakeAttestationResponseAsync();

            Assert.Equal(_aaguid, credential.AaGuid);
            Assert.Equal(_signCount, credential.SignCount);
            Assert.Equal("none", credential.AttestationFormat);
            Assert.Equal(_credentialID, credential.Id);
            Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
            Assert.Equal("Test User", credential.User.DisplayName);
            Assert.Equal("testuser"u8.ToArray(), credential.User.Id);
            Assert.Equal("testuser", credential.User.Name);

            // WebAuthn L3 §7.1 step 26: the credential record records the rp.id the ceremony was run under.
            Assert.Equal(rp, credential.RpId);

            _attestationObject = new CborMap { { "fmt", "none" } };
        }
    }

    [Fact]
    public async Task TestNoneSurfacesAuthenticatorExtensionOutputs()
    {
        // WebAuthn L3 §7.1 step 27: the Relying Party processes the authenticator extension outputs in authData.
        _authenticatorExtensions = new CborMap
        {
            { "credProtect", 0x03 },
            { "minPinLength", 6 },
            { "hmac-secret", true }
        };

        _attestationObject.Add("attStmt", new CborMap());
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);

        var credential = await MakeAttestationResponseAsync();

        Assert.Equal(CredentialProtectionPolicy.UserVerificationRequired, credential.AuthenticatorExtensionResults.CredProtect);
        Assert.Equal(6u, credential.AuthenticatorExtensionResults.MinPinLength);
        Assert.True(credential.AuthenticatorExtensionResults.HmacSecret);
    }

    [Fact]
    public async Task TestNoneWithAttStmt()
    {
        _attestationObject.Add("attStmt", new CborMap { { "foo", "bar" } });
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Attestation format none should have no attestation statement", ex.Message);
    }
}
