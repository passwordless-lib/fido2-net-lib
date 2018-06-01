using fido2NetLib;
using Newtonsoft.Json;
using System;
using System.IO;
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
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./json1.json"));
            var options = JsonConvert.DeserializeObject<OptionsResponse>(File.ReadAllText("./options1.json"));

            Assert.NotNull(jsonPost);

            var fido2 = new Fido2NetLib(new Fido2NetLib.Configuration());
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            ReadOnlySpan<byte> ad = o.AttestionObject.AuthData;

            Assert.Equal(32,AuthDataHelper.GetRpIdHash(ad).Length);
            Assert.True(AuthDataHelper.IsUserPresent(ad)); // better test needed

            var counter = AuthDataHelper.GetSignCount(ad); // how to test this?

            Assert.False(AuthDataHelper.IsUserVerified(ad));

            Assert.True(AuthDataHelper.HasAttested(ad));

            var aaguid = AuthDataHelper.GetAttestionData(new Memory<byte>(o.AttestionObject.AuthData));



        }
    }
}
