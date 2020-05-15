﻿using System.Linq;
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
            Fido2Tests._validCOSEParameters.ForEach(async delegate (object[] param)
            {
                _attestationObject.Add("attStmt", CBORObject.NewMap());
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
                Assert.Equal(System.Text.Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id);
                Assert.Equal("testuser", res.Result.User.Name);
                _attestationObject = CBORObject.NewMap().Add("fmt", "none");
            });
        }
        [Fact]
        public void TestNoneWithAttStmt()
        {
            _attestationObject.Add("attStmt", CBORObject.NewMap().Add("foo", "bar"));
            _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponse());
            Assert.Equal("Attestation format none should have no attestation statement", ex.Result.Message);
        }
    }
}
