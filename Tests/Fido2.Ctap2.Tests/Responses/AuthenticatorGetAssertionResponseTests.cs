using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorGetAssertionResponseTests
{
    [Fact]
    public void Deserialize()
    {
        string hexEncodedCborData = """

            00                                      # status = success
            a5                                      # map(5)
               01                                   # unsigned(1) - Credential
               a2                                   # map(2)
                  62                                # text(2)
                     6964                           # "id"
                  58 40                             # bytes(64)
                     f22006de4f905af68a43942f02     # credential ID
                     4f2a5ece603d9c6d4b3df8be08     # ...
                     ed01fc442646d034858ac75bed     # ...
                     3fd580bf9808d94fcbee82b9b2     # ...
                     ef6677af0adcc35852ea6b9e       # ...
                  64                                # text(4)
                     74797065                       # "type"
                  6a                                # text(10)
                     7075626C69632D6B6579           # "public-key"
               02                                   # unsigned(2)
               58 25                                # bytes(37)
                  625ddadf743f5727e66bba8c2e387922  # authData
                  d1af43c503d9114a8fba104d84d02bfa  # ...
                  0100000011                        # ...
               03                                   # unsigned(3)
               58 47                                # bytes(71)
                  304502204a5a9dd39298149d904769b5  # signature
                  1a451433006f182a34fbdf66de5fc717  # ...
                  d75fb350022100a46b8ea3c3b933821c  # ...
                  6e7f5ef9daae94ab47f18db474c74790  # ...
                  eaabb14411e7a0                    # ...
               04                                   # unsigned(4) - publicKeyCredentialUserEntity
               a4                                   # map(4)
                 62                                 # text(2)
                    6964                            # "id"
                  58 20                             # bytes(32)
                    3082019330820138a003020102      # userid
                    3082019330820138a003020102      # ...
                    308201933082                    # ...
                  64                                # text(4)
                    69636f6e                        # "icon"
                  782b                              # text(43)
                    68747470733a2f2f706963732e6578  # "https://pics.example.com/00/p/aBjjjpqPb.png"
                    616d706c652e636f6d2f30302f702f  # ...
                    61426a6a6a707150622e706e67      # ...
                 64                                 # text(4)
                    6e616d65                        # "name"
                 76                                 # text(22)
                    6a6f686e70736d697468406578616d  # "johnpsmith@example.com"
                    706c652e636f6d                  # ...
                 6b                                 # text(11)
                    646973706c61794e616d65          # "displayName"
                 6d                                 # text(13)
                    4a6f686e20502e20536d697468      # "John P. Smith"
               05                                   # unsigned(5) - numberofCredentials
               01                                   # unsigned(1)
            """;

        var response = AuthenticatorGetAssertionResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Equal("f22006de4f905af68a43942f024f2a5ece603d9c6d4b3df8be08ed01fc442646d034858ac75bed3fd580bf9808d94fcbee82b9b2ef6677af0adcc35852ea6b9e", Convert.ToHexString(response.Credential!.Id).ToLower());
        Assert.Equal(PublicKeyCredentialType.PublicKey, response.Credential.Type);

        Assert.Equal(37, response.AuthData.Length);
        Assert.Equal(71, response.Signature.Length);

        Assert.Equal(32,                                            response.User!.Id.Length);
        Assert.Equal("https://pics.example.com/00/p/aBjjjpqPb.png", response.User!.Icon);
        Assert.Equal("johnpsmith@example.com",                      response.User!.Name);
        Assert.Equal("John P. Smith",                               response.User!.DisplayName);

        Assert.Equal(1, response.NumberOfCredentials!.Value);


    }
}
