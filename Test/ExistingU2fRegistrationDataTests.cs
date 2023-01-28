using System.Security.Cryptography;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace fido2_net_lib.Test;

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
            AllowCredentials = new PublicKeyCredentialDescriptor[]
            {
                new(keyHandleData)
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

        IFido2 fido2 = new Fido2(new Fido2Configuration
        {
            Origins = new HashSet<string> { "https://localhost:44336" } //data was generated with this origin
        });

        var res = await fido2.MakeAssertionAsync(authResponse, options, publicKey.Encode(), 0, null);

        Assert.Equal("ok", res.Status);
    }

    public static CborMap CreatePublicKeyFromU2fRegistrationData(byte[] keyHandleData, byte[] publicKeyData)
    {
        var x = new byte[32];
        var y = new byte[32];
        Buffer.BlockCopy(publicKeyData, 1, x, 0, 32);
        Buffer.BlockCopy(publicKeyData, 33, y, 0, 32);

        var point = new ECPoint
        {
            X = x,
            Y = y,
        };

        var coseKey = new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, COSE.KeyType.EC2 },
            { (int)COSE.KeyCommonParameter.Alg, -7 },

            { COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P256 },

            { COSE.KeyTypeParameter.X, point.X },
            { COSE.KeyTypeParameter.Y, point.Y }
        };

        return coseKey;
    }
}
