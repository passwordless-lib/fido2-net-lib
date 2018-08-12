using fido2NetLib;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace fido2_net_lib.Test
{
    // todo: Create tests and name Facts and json files better.
    public class UnitTest1
    {
        public static byte[] StringToByteArray(string hex)
        {
            hex = hex.Replace("-", "");
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        private T Get<T>(string filename)
        {
            return JsonConvert.DeserializeObject<T>(File.ReadAllText(filename));
        }

        [Fact]
        public void TestFido2Assertion()
        {
            //var existingKey = "45-43-53-31-20-00-00-00-0E-B4-F3-73-C2-AC-7D-F7-7E-7D-17-D3-A3-A2-CC-AB-E5-C6-B1-42-ED-10-AC-7C-15-72-39-8D-75-C6-5B-B9-76-09-33-A0-30-F2-44-51-C8-31-AF-72-9B-4F-7B-AB-4F-85-2D-7D-1F-E0-B5-BD-A3-3D-0E-D6-18-04-CD-98";
            
            //var key2 = "45-43-53-31-20-00-00-00-1D-60-44-D7-92-A0-0C-1E-3B-F9-58-5A-28-43-92-FD-F6-4F-BB-7F-8E-86-33-38-30-A4-30-5D-4E-2C-71-E3-53-3C-7B-98-81-99-FE-A9-DA-D9-24-8E-04-BD-C7-86-40-D3-03-1E-6E-00-81-7D-85-C3-A2-19-C9-21-85-8D";
            //var key2 = "45-43-53-31-20-00-00-00-A9-E9-12-2A-37-8A-F0-74-E7-BA-52-54-B0-91-55-46-DB-21-E5-2C-01-B8-FB-69-CD-E5-ED-02-B6-C3-16-E3-1A-59-16-C1-43-87-0D-04-B9-94-7F-CF-56-E5-AA-5E-96-8C-5B-27-8F-83-F4-E2-50-AB-B3-F6-28-A1-F8-9E";



            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestionNoneOptions.json"));
            var response = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestionNoneResponse.json"));

            var fido2 = new fido2NetLib.Fido2NetLib(new Fido2NetLib.Configuration()
            {
                ServerDomain = "localhost",
                Origin = "https://localhost:44329"
            });

            var o = AuthenticatorAttestationResponse.Parse(response);
            o.Verify(options, "https://localhost:44329");

            var credId = "F1-3C-7F-08-3C-A2-29-E0-B4-03-E8-87-34-6E-FC-7F-98-53-10-3A-30-91-75-67-39-7A-D1-D8-AF-87-04-61-87-EF-95-31-85-60-F3-5A-1A-2A-CF-7D-B0-1D-06-B9-69-F9-AB-F4-EC-F3-07-3E-CF-0F-71-E8-84-E8-41-20";
            var allowedCreds = new List<PublicKeyCredentialDescriptor>() {
                    new PublicKeyCredentialDescriptor()
                    {
                        Id = StringToByteArray(credId),
                        Type = "public-key"
                    }
                };

            // assertion

            var aoptions = Get<AssertionOptions>("./assertionNoneOptions.json");
            AuthenticatorAssertionRawResponse aresponse = Get<AuthenticatorAssertionRawResponse>("./assertionNoneResponse.json");

            // signed assertion?
            //var cng = CngKey.Import(StringToByteArray(key2), CngKeyBlobFormat.EccPublicBlob);
            //var existingPublicKey = new ECDsaCng(cng);
            //fido2.MakeAssertion(aresponse, aoptions, response.);


        }

        [Fact]
        public void TestParsing()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./json1.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./options1.json"));

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
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./options2.json"));

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
        }
        
        [Fact]
        public void TestU2FAttestation()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsU2F.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsU2F.json"));
            var fido2 = new Fido2NetLib(new Fido2NetLib.Configuration());
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            o.Verify(options, "https://localhost:44329");
            ReadOnlySpan<byte> ad = o.AttestionObject.AuthData;
            Assert.True(AuthDataHelper.IsUserPresent(ad));
            Assert.False(AuthDataHelper.IsUserVerified(ad));
        }
        [Fact]
        public void TestPackedAttestation()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsPacked.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsPacked.json"));
            var fido2 = new Fido2NetLib(new Fido2NetLib.Configuration());
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            o.Verify(options, "https://localhost:44329");
            ReadOnlySpan<byte> ad = o.AttestionObject.AuthData;
            Assert.True(AuthDataHelper.IsUserPresent(ad));
            Assert.True(AuthDataHelper.IsUserVerified(ad));
        }
        [Fact]
        public void TestNoneAttestation()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsNone.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsNone.json"));
            var fido2 = new Fido2NetLib(new Fido2NetLib.Configuration());
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            o.Verify(options, "https://localhost:44329");
        }
        //public void TestHasCorrentAAguid()
        //{
        //    var expectedAaguid = new Uint8Array([
        //    0x42, 0x38, 0x32, 0x45, 0x44, 0x37, 0x33, 0x43, 0x38, 0x46, 0x42, 0x34, 0x45, 0x35, 0x41, 0x32
        //]).buffer;
        //}
    }
}
