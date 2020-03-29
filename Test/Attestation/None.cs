using System.Linq;
using fido2_net_lib.Test;
using Fido2NetLib;
using Fido2NetLib.Objects;
using PeterO.Cbor;
using Xunit;

namespace Test.Attestation
{
    public class None : Fido2Tests.Attestation
    {
        public None()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "none");
        }
        [Fact]
        public void TestNone()
        {
            Fido2Tests._validCOSEParameters.ForEach(delegate (object[] param)
            {
                _attestationObject.Add("attStmt", CBORObject.NewMap());
                _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(param);
                Fido2.CredentialMakeResult res = null;

                res = MakeAttestationResponse().Result;

                Assert.Equal("none", res.Result.CredType);
                //Assert.Equal(new byte[] { 0xf1, 0xd0 }, res.Result.CredentialId);
                Assert.True(new[] { res.Status, res.Status }.All(x => x == "ok"));
                Assert.True(new[] { res.ErrorMessage, res.ErrorMessage }.All(x => x == ""));
                //Assert.True(res.Result.Counter + 1 == res.Result.Counter);
                _attestationObject = CBORObject.NewMap().Add("fmt", "none");
            });
        }
        [Fact]
        public void TestNoneWithAttStmt()
        {
            _attestationObject.Add("attStmt", CBORObject.NewMap().Add("foo", "bar"));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse(_attestationObject, COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256));
            Assert.Equal("Attestation format none should have no attestation statement", ex.Result.Message);
        }
    }
}
