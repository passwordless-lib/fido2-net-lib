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
            MakeNewCredentialResult res;

            res = await MakeAttestationResponseAsync();

            Assert.Equal(_aaguid, res.Credential.AaGuid);
            Assert.Equal(_signCount, res.Credential.SignCount);
            Assert.Equal("none", res.Credential.AttestationFormat);
            Assert.Equal(_credentialID, res.Credential.Id);
            Assert.Equal(_credentialPublicKey.GetBytes(), res.Credential.PublicKey);
            Assert.Equal("Test User", res.Credential.User.DisplayName);
            Assert.Equal("testuser"u8.ToArray(), res.Credential.User.Id);
            Assert.Equal("testuser", res.Credential.User.Name);
            _attestationObject = new CborMap { { "fmt", "none" } };
        }
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
