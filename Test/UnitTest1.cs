using Fido2NetLib.Objects;
using Fido2NetLib;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;
using System.Threading.Tasks;

namespace fido2_net_lib.Test
{
    // todo: Create tests and name Facts and json files better.
    public class UnitTest1
    {
        internal IMetadataService MetadataService;
        private readonly Configuration config;

        public UnitTest1()
        {
            var MDSAccessKey = Environment.GetEnvironmentVariable("fido2:MDSAccessKey");
            var CacheDir = Environment.GetEnvironmentVariable("fido2:MDSCacheDirPath");

            // Only create and use MetadataService if we have an accesskey
            MetadataService = string.IsNullOrEmpty(MDSAccessKey) ? null : MDSMetadata.Instance(MDSAccessKey, CacheDir);
            if (null != MetadataService)
            {
                if (false == MetadataService.IsInitialized())
                    MetadataService.Initialize().Wait();
            }
            config = new Configuration { Origin = "https://localhost:44329" };
        }
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
        public void TestStringIsSerializable()
        {
            var x2 = new AuthenticatorSelection();
            x2.UserVerification = UserVerificationRequirement.Discouraged;
            var json = JsonConvert.SerializeObject(x2);
            var c3 = JsonConvert.DeserializeObject<AuthenticatorSelection>(json);

            Assert.Equal(UserVerificationRequirement.Discouraged, c3.UserVerification);

            Assert.NotEqual(UserVerificationRequirement.Required, c3.UserVerification);

            // Assert.True("discouraged" == UserVerificationRequirement.Discouraged);
            // Assert.False("discouraged" != UserVerificationRequirement.Discouraged);

            Assert.False(UserVerificationRequirement.Required == UserVerificationRequirement.Discouraged);
            Assert.True(UserVerificationRequirement.Required != UserVerificationRequirement.Discouraged);

            // testing where string and membername mismatch

            var y1 = AuthenticatorAttachment.CrossPlatform;
            var yjson = JsonConvert.SerializeObject(y1);
            Assert.Equal("\"cross-platform\"", yjson);

            var y2 = JsonConvert.DeserializeObject<AuthenticatorAttachment>(yjson);

            Assert.Equal(AuthenticatorAttachment.CrossPlatform, y2);

            // test list of typedstrings
            var z1 = new[] { AuthenticatorTransport.Ble, AuthenticatorTransport.Usb, AuthenticatorTransport.Nfc };
            var zjson = JsonConvert.SerializeObject(z1);
            var z2 = JsonConvert.DeserializeObject<AuthenticatorTransport[]>(zjson);

            Assert.All(z2, (x) => z1.Contains(x));
            Assert.True(z1.SequenceEqual(z2));

        }

        [Fact]
        public async Task TestFido2AssertionAsync()
        {
            //var existingKey = "45-43-53-31-20-00-00-00-0E-B4-F3-73-C2-AC-7D-F7-7E-7D-17-D3-A3-A2-CC-AB-E5-C6-B1-42-ED-10-AC-7C-15-72-39-8D-75-C6-5B-B9-76-09-33-A0-30-F2-44-51-C8-31-AF-72-9B-4F-7B-AB-4F-85-2D-7D-1F-E0-B5-BD-A3-3D-0E-D6-18-04-CD-98";

            //var key2 = "45-43-53-31-20-00-00-00-1D-60-44-D7-92-A0-0C-1E-3B-F9-58-5A-28-43-92-FD-F6-4F-BB-7F-8E-86-33-38-30-A4-30-5D-4E-2C-71-E3-53-3C-7B-98-81-99-FE-A9-DA-D9-24-8E-04-BD-C7-86-40-D3-03-1E-6E-00-81-7D-85-C3-A2-19-C9-21-85-8D";
            //var key2 = "45-43-53-31-20-00-00-00-A9-E9-12-2A-37-8A-F0-74-E7-BA-52-54-B0-91-55-46-DB-21-E5-2C-01-B8-FB-69-CD-E5-ED-02-B6-C3-16-E3-1A-59-16-C1-43-87-0D-04-B9-94-7F-CF-56-E5-AA-5E-96-8C-5B-27-8F-83-F4-E2-50-AB-B3-F6-28-A1-F8-9E";

            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./AttestationNoneOptions.json"));
            var response = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./AttestationNoneResponse.json"));

            var o = AuthenticatorAttestationResponse.Parse(response);
            await o.VerifyAsync(options, config, (x) => Task.FromResult(true), MetadataService, null);

            var credId = "F1-3C-7F-08-3C-A2-29-E0-B4-03-E8-87-34-6E-FC-7F-98-53-10-3A-30-91-75-67-39-7A-D1-D8-AF-87-04-61-87-EF-95-31-85-60-F3-5A-1A-2A-CF-7D-B0-1D-06-B9-69-F9-AB-F4-EC-F3-07-3E-CF-0F-71-E8-84-E8-41-20";
            var allowedCreds = new List<PublicKeyCredentialDescriptor>() {
                    new PublicKeyCredentialDescriptor()
                    {
                        Id = StringToByteArray(credId),
                        Type = PublicKeyCredentialType.PublicKey
                    }
                };

            // assertion

            var aoptions = Get<AssertionOptions>("./assertionNoneOptions.json");
            var aresponse = Get<AuthenticatorAssertionRawResponse>("./assertionNoneResponse.json");

            // signed assertion?
            //var cng = CngKey.Import(StringToByteArray(key2), CngKeyBlobFormat.EccPublicBlob);
            //var existingPublicKey = new ECDsaCng(cng);
            //fido2.MakeAssertion(aresponse, aoptions, response.);


        }

        [Fact]
        public async Task TestParsingAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./json1.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./options1.json"));

            Assert.NotNull(jsonPost);

            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, config, (x) => Task.FromResult(true), MetadataService, null);
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
        public async Task TestU2FAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsU2F.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsU2F.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, config, (x) => Task.FromResult(true), MetadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
        }
        [Fact]
        public async Task TestPackedAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsPacked.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsPacked.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, config, (x) => Task.FromResult(true), MetadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
        }
        [Fact]
        public async Task TestNoneAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsNone.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsNone.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, config, (x) => Task.FromResult(true), MetadataService, null);
        }
        [Fact]
        public async Task TestTPMSHA256AttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationTPMSHA256Response.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationTPMSHA256Options.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, config, (x) => Task.FromResult(true), MetadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
        }
        [Fact]
        public async Task TestTPMSHA1AttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationTPMSHA1Response.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationTPMSHA1Options.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, config, (x) => Task.FromResult(true), MetadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
        }
        [Fact]
        public async Task TestAndroidKeyAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationAndroidKeyResponse.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationAndroidKeyOptions.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, config, (x) => Task.FromResult(true), MetadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
        }
        [Fact]
        public async Task TaskPackedAttestation512()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsPacked512.json"));
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(File.ReadAllText("./attestationOptionsPacked512.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);
            await o.VerifyAsync(options, config, (x) => Task.FromResult(true), MetadataService, null);
            byte[] ad = o.AttestationObject.AuthData;
        }
        //public void TestHasCorrentAAguid()
        //{
        //    var expectedAaguid = new Uint8Array([
        //    0x42, 0x38, 0x32, 0x45, 0x44, 0x37, 0x33, 0x43, 0x38, 0x46, 0x42, 0x34, 0x45, 0x35, 0x41, 0x32
        //]).buffer;
        //}
    }
}
