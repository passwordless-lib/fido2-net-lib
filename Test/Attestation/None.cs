using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using System.Runtime.InteropServices;

namespace Test.Attestation;

public class None : Fido2Tests.Attestation
{
    public None()
    {
        _attestationObject = new CborMap { { "fmt", "none" } };
    }

    [Fact]
    public void TestNone()
    {
        Fido2Tests._validCOSEParameters.ForEach(async ((COSE.KeyType, COSE.Algorithm, COSE.EllipticCurve) param) =>
        {
            // No support for P256K on OSX
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) && param.Item3 == COSE.EllipticCurve.P256K)
                return;

            _attestationObject.Add("attStmt", new CborMap());
            _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(param);
            Fido2.CredentialMakeResult res = null;

            res = await MakeAttestationResponseAsync();

            Assert.Equal(string.Empty, res.ErrorMessage);
            Assert.Equal("ok", res.Status);
            Assert.Equal(_aaguid, res.Result.AaGuid);
            Assert.Equal(_signCount, res.Result.Counter);
            Assert.Equal("none", res.Result.CredType);
            Assert.Equal(_credentialID, res.Result.CredentialId);
            Assert.Null(res.Result.ErrorMessage);
            Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
            Assert.Null(res.Result.Status);
            Assert.Equal("Test User", res.Result.User.DisplayName);
            Assert.Equal("testuser"u8.ToArray(), res.Result.User.Id);
            Assert.Equal("testuser", res.Result.User.Name);
            _attestationObject = new CborMap { { "fmt", "none" } };
        });
    }

    [Fact]
    public async Task TestNoneWithAttStmt()
    {
        _attestationObject.Add("attStmt", new CborMap { { "foo", "bar" } });
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal("Attestation format none should have no attestation statement", ex.Message);
    }
}
