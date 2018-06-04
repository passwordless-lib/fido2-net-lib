using fido2NetLib;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Linq;
using Xunit;

namespace fido2_net_lib.Test
{
    // todo: Create tests and name Facts and json files better.
    public class UnitTest1
    {
        [Fact]
        public void TestParsing()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./json1.json"));
            var options = JsonConvert.DeserializeObject<OptionsResponse>(File.ReadAllText("./options1.json"));

            Assert.NotNull(jsonPost);

            var fido2 = new fido2NetLib.Fido2NetLib(new Fido2NetLib.Configuration());
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            o.Verify(options, "https://localhost:44329");
        }

        [Fact]
        public void TestAuthenticatorDataPa2rsing()
        {
            var bs = new byte[] { 1, 2, 3 };
            var x = PeterO.Cbor.CBORObject.NewMap().Add("bytes", bs);
            var s = x["bytes"].GetByteString();

            Assert.Equal(s, bs);
        }



        [Fact]
        public void TestAuthenticatorDataParsing()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./json2.json"));
            var options = JsonConvert.DeserializeObject<OptionsResponse>(File.ReadAllText("./options2.json"));

            Assert.NotNull(jsonPost);

            var fido2 = new Fido2NetLib(new Fido2NetLib.Configuration());
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            ReadOnlySpan<byte> ad = o.AttestionObject.AuthData;

            Assert.Equal(32, AuthDataHelper.GetRpIdHash(ad).Length);

            var exptecRpIdHash = new uint[]
            {
                0x95, 0x69, 0x08, 0x8F, 0x1E, 0xCE, 0xE3, 0x23, 0x29, 0x54, 0x03, 0x5D, 0xBD, 0x10, 0xD7, 0xCA,
            0xE3, 0x91, 0x30, 0x5A, 0x27, 0x51, 0xB5, 0x59, 0xBB, 0x8F, 0xD7, 0xCB, 0xB2, 0x29, 0xBD, 0xD4,
            };

            Assert.Equal(exptecRpIdHash, AuthDataHelper.GetRpIdHash(ad).ToArray().Select(y => (uint)y));

            Assert.True(AuthDataHelper.IsUserPresent(ad)); // better test needed

            var counter = AuthDataHelper.GetSignCount(ad); // how to test this?
            Assert.Equal((uint)1, counter);
            Assert.False(AuthDataHelper.IsUserVerified(ad));

            Assert.True(AuthDataHelper.HasAttested(ad));

            var authData = AuthDataHelper.GetAttestionData(new Memory<byte>(o.AttestionObject.AuthData));
            var expectedAaguid = new byte[] {
                0x42, 0x38, 0x32, 0x45, 0x44, 0x37, 0x33, 0x43, 0x38, 0x46, 0x42, 0x34, 0x45, 0x35, 0x41, 0x32
            };

            Assert.Equal(expectedAaguid, authData.aaguid.ToArray());

            var expectedPublicKeyCose = new byte[]
            {
                0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x59, 0x1D, 0xC1, 0xE1, 0x04, 0xEA,
            0x65, 0xA2, 0x20, 0x06, 0x0F, 0x0E, 0x82, 0xB3, 0xDF, 0xCF, 0x35, 0x02, 0x86, 0xB8, 0xB2, 0x7F,
            0x33, 0x91, 0x39, 0xB4, 0x68, 0xF2, 0x8A, 0x60, 0x1B, 0xDD, 0x22, 0x58, 0x20, 0xB6, 0x51, 0xB7,
            0xDA, 0x5C, 0x6B, 0x6A, 0x78, 0x3C, 0x33, 0x4B, 0x68, 0x8D, 0x82, 0x77, 0xE8, 0x22, 0xF5, 0x54,
            0xCB, 0xF6, 0xA5, 0x94, 0xB3, 0xA9, 0x1F, 0xCD, 0x7E, 0xF1, 0xBC, 0xF1, 0xB0
            };

            Assert.Equal(expectedPublicKeyCose, authData.credentialPublicKey.ToArray());

            var x = PeterO.Cbor.CBORObject.DecodeFromBytes(authData.credentialPublicKey.ToArray());
            var json = x.ToJSONString();
        }

        //public void TestHasCorrentAAguid()
        //{
        //    var expectedAaguid = new Uint8Array([
        //    0x42, 0x38, 0x32, 0x45, 0x44, 0x37, 0x33, 0x43, 0x38, 0x46, 0x42, 0x34, 0x45, 0x35, 0x41, 0x32
        //]).buffer;
        //}
    }
}
