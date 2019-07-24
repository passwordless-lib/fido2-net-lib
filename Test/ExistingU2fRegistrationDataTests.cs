using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using PeterO.Cbor;
using Xunit;

namespace fido2_net_lib.Test
{
    public class ExistingU2fRegistrationDataTests
    {
        [Fact]
        public async Task TestFido2AssertionWithExistingU2fRegistrationWithAppId()
        {
            // u2f registration with appId
            var appId = "https://localhost:44336";
            var keyHandleData = Base64Url.Decode("2uzGTqu9XGoDQpRBhkv3qDYWzEEZrDjOHT94fHe3J9VXl6KpaY6jL1C4gCAVSBCWZejOn-EYSyXfiG7RDQqgKw");
            var publicKeyData = Base64Url.Decode("BEKJkJiDzo8wlrYbAHmyz5a5vShbkStO58ZO7F-hy4fvBp6TowCZoV2dNGcxIN1yT18799bb_WuP0Yq_DSv5a-U");

            //key as cbor
            var publicKey = CreatePublicKeyFromU2fRegistrationData(keyHandleData, publicKeyData);

            var options = new AssertionOptions
            {
                Challenge = Base64Url.Decode("mNxQVDWI8+ahBXeQJ8iS4jk5pDUd5KetZGVOwSkw2X0"),
                RpId = "localhost",
                AllowCredentials = new[]
                {
                    new PublicKeyCredentialDescriptor
                    {
                          Id = keyHandleData,
                          Type = PublicKeyCredentialType.PublicKey
                    }
                },
                Extensions = new AuthenticationExtensionsClientInputs
                {
                    AppID = appId
                }
            };

            var authResponse = new AuthenticatorAssertionRawResponse
            {
                Id = keyHandleData,
                RawId = keyHandleData,
                Type = PublicKeyCredentialType.PublicKey,
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = true
                },
                Response = new AuthenticatorAssertionRawResponse.AssertionResponse
                {
                    AuthenticatorData = Base64Url.Decode("B6_fPoU4uitIYRHXuNfpbqt5mrDWz8cp7d1noAUrAucBAAABTQ"),
                    ClientDataJson = Base64Url.Decode("eyJjaGFsbGVuZ2UiOiJtTnhRVkRXSTgtYWhCWGVRSjhpUzRqazVwRFVkNUtldFpHVk93U2t3MlgwIiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NDQzMzYiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0"),
                    Signature = Base64Url.Decode("MEQCICHV36RVY9DdFmKZgxF5Z_yScpPPsKcj__8KcPmngtGHAiAq_SzmTY8rZz4-5uNNiz3h6xO9osNTh7O7Mjqtoxul8w")
                }
            };

            var fido2 = new Fido2(new Configuration
            {
                Origin = "https://localhost:44336" //data was generated with this origin
            });

            var res = await fido2.MakeAssertionAsync(authResponse, options, publicKey.EncodeToBytes(), 0, null);

            Assert.Equal("ok", res.Status);

        }

        public static CBORObject CreatePublicKeyFromU2fRegistrationData(byte[] keyHandleData, byte[] publicKeyData)
        {
            var publicKey = new ECDsaCng(ConvertPublicKey(publicKeyData));

            var coseKey = CBORObject.NewMap();

            coseKey.Add(COSE.KeyCommonParameter.KeyType, COSE.KeyType.EC2);
            coseKey.Add(COSE.KeyCommonParameter.Alg, -7);

            var keyParams = publicKey.ExportParameters(false);

            if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP256.Oid.FriendlyName))
                coseKey.Add(COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P256);

            coseKey.Add(COSE.KeyTypeParameter.X, keyParams.Q.X);
            coseKey.Add(COSE.KeyTypeParameter.Y, keyParams.Q.Y);

            return coseKey;

        }

        public static CngKey ConvertPublicKey(byte[] rawData)
        {
            if (rawData == null || rawData.Length != 65)
                throw new Exception();
            var header = new byte[] { 0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00 };
            var eccPublicKeyBlob = new byte[72];
            Array.Copy(header, 0, eccPublicKeyBlob, 0, 8);
            Array.Copy(rawData, 1, eccPublicKeyBlob, 8, 64);
            CngKey key = CngKey.Import(eccPublicKeyBlob, CngKeyBlobFormat.EccPublicBlob);
            return key;
        }
    }
}
