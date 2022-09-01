using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

using Xunit;

namespace Test.Attestation
{
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
                _attestationObject.Add("attStmt", new CborMap());
                _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(param);
                Fido2.CredentialMakeResult res = null;

                res = await MakeAttestationResponse();

                Assert.Equal(string.Empty, res.ErrorMessage);
                Assert.Equal("ok", res.Status);
                Assert.Equal(_aaguid, res.Result.Aaguid);
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
        public void TestNoneWithAttStmt()
        {
            _attestationObject.Add("attStmt", new CborMap { { "foo", "bar" } });
            _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Attestation format none should have no attestation statement", ex.Result.Message);
        }
    }
}
