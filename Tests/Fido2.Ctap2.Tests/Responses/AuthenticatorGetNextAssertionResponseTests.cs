using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorGetNextAssertionResponseTests
{
    [Fact]
    public void Deserialize()
    {
        string hexEncodedCborData = """

            00                                      # status = success
            a4                                      # map(4)
               01                                   # unsigned(1) - Credential
               a2                                   # map(2)
                  62                                # text(2)
                     6964                           # "id"
                  48                                # bytes(8)
                     f22006de4f905af6               # credential ID
                  64                                # text(4)
                     74797065                       # "type"
                  6a                                # text(10)
                     7075626C69632D6B6579           # "public-key"
               02                                   # unsigned(2) - authData
               43                                   # bytes(3)
                  010203                            # ...
               03                                   # unsigned(3) - signature
               44                                   # bytes(4)
                  04050607                          # ...
               04                                   # unsigned(4) - publicKeyCredentialUserEntity
               a1                                   # map(1)
                  62                                # text(2)
                     6964                           # "id"
                  42                                # bytes(2)
                     aabb                           # userid
            """;

        var response = AuthenticatorGetNextAssertionResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Equal("f22006de4f905af6", Convert.ToHexString(response.Credential!.Id).ToLower());
        Assert.Equal(PublicKeyCredentialType.PublicKey, response.Credential.Type);

        Assert.Equal(3, response.AuthData.Length);
        Assert.Equal(4, response.Signature.Length);

        Assert.Equal("aabb", Convert.ToHexString(response.User!.Id).ToLower());
    }

    [Fact]
    public void DeserializeWithoutCredential()
    {
        // Per CTAP2, Credential (0x01) may be omitted when the preceding getAssertion's allowList had exactly
        // one entry -- the platform is expected to already know which credential this is.
        string hexEncodedCborData = """

            00                                      # status = success
            a2                                      # map(2)
               02                                   # unsigned(2) - authData
               43                                   # bytes(3)
                  010203                            # ...
               03                                   # unsigned(3) - signature
               44                                   # bytes(4)
                  04050607                          # ...
            """;

        var response = AuthenticatorGetNextAssertionResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Null(response.Credential);
        Assert.Null(response.User);
        Assert.Equal(3, response.AuthData.Length);
        Assert.Equal(4, response.Signature.Length);
    }
}
