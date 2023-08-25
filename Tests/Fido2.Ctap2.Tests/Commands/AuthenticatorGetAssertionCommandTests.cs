using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorGetAssertionCommandTests
{
    [Fact]
    public void GetPayload()
    {
        var request = new AuthenticatorGetAssertionCommand(
            rpId: "example.com",
            clientDataHash: Convert.FromHexString("687134968222ec17202e42505f8ed2b16ae22f16bb05b88c25db9e602645f141"),
            allowList: new[]
            {
                new  PublicKeyCredentialDescriptor(Convert.FromHexString("f22006de4f905af68a43942f024f2a5ece603d9c6d4b3df8be08ed01fc442646d034858ac75bed3fd580bf9808d94fcbee82b9b2ef6677af0adcc35852ea6b9e")),
                new  PublicKeyCredentialDescriptor(Convert.FromHexString("0303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303"))
            },
            options: new AuthenticatorGetAssertionOptions { UserVerification = true }

        );

        string expect = """
            02                                      # authenticatorGetAssertion command
            a4                                      # map(4)
               01                                   # unsigned(1)
               6b                                   # text(11)
                  6578616d706c652e636f6d            # "example.com"
               02                                   # unsigned(2)
               58 20                                # bytes(32)
                  687134968222ec17202e42505f8ed2b1  # clientDataHash
                  6ae22f16bb05b88c25db9e602645f141  # ...
               03                                   # unsigned(3)
               82                                   # array(2)
                  a2                                # map(2)
                     62                             # text(2)
                        6964                        # "id"
                     58 40                          # bytes(64)
                        f22006de4f905af68a43942f02  # credential ID
                        4f2a5ece603d9c6d4b3df8be08  # ...
                        ed01fc442646d034858ac75bed  # ...
                        3fd580bf9808d94fcbee82b9b2  # ...
                        ef6677af0adcc35852ea6b9e    # ...
                     64                             # text(4)
                        74797065                    # "type"
                     6a                             # text(10)
                        7075626C69632D6B6579        # "public-key"
                  a2                                # map(2)
                     62                             # text(2)
                        6964                        # "id"
                     58 32                          # bytes(50)
                        03030303030303030303030303  # credential ID
                        03030303030303030303030303  # ...
                        03030303030303030303030303  # ...
                        0303030303030303030303      # ...
                     64                             # text(4)
                        74797065                    # "type"
                     6a                             # text(10)
                        7075626C69632D6B6579        # "public-key"
               05                                   # unsigned(5)
               a1                                   # map(1)
                  62                                # text(2)
                     7576                           # "uv"
                  f5                                # true

            """;

        Assert.Equal(TestHelper.GetCborEncodedHexString(expect).ToLower(), Convert.ToHexString(request.GetPayload()).ToLower());
    }
}
