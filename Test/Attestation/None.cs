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
        public override CredentialPublicKey _credentialPublicKey => throw new System.NotImplementedException();

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
                (Fido2.CredentialMakeResult, AssertionVerificationResult) res;

                if (param.Length == 3)
                {
                    res = MakeAttestationResponse(_attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1], (COSE.EllipticCurve)param[2]).Result;
                }
                else
                {
                    res = MakeAttestationResponse(_attestationObject, (COSE.KeyType)param[0], (COSE.Algorithm)param[1]).Result;
                }

                Assert.Equal("none", res.Item1.Result.CredType);
                Assert.Equal(new byte[] { 0xf1, 0xd0 }, res.Item2.CredentialId);
                Assert.True(new[] { res.Item1.Status, res.Item2.Status }.All(x => x == "ok"));
                Assert.True(new[] { res.Item1.ErrorMessage, res.Item2.ErrorMessage }.All(x => x == ""));
                Assert.True(res.Item1.Result.Counter + 1 == res.Item2.Counter);
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
