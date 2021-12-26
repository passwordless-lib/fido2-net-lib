using System;

using Fido2NetLib.Objects;

using Xunit;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorMakeCredentialCommandTests
{
    [Fact]
    public void GetPayload()
    {
        var request = new AuthenticatorMakeCredentialCommand(
            clientDataHash: Convert.FromHexString("687134968222ec17202e42505f8ed2b16ae22f16bb05b88c25db9e602645f141"),
            rpEntity: new PublicKeyCredentialRpEntity(id: "example.com", name: "Acme", null),
            user: new PublicKeyCredentialUserEntity {
                    Id          = Convert.FromHexString("3082019330820138a0030201023082019330820138a003020102308201933082"),
                    Icon        = "https://pics.example.com/00/p/aBjjjpqPb.png",
                    Name        = "johnpsmith@example.com",
                    DisplayName = "John P. Smith"
                            
            },
            pubKeyCredParams: new[] { 
                new PubKeyCredParam(COSE.Algorithm.ES256), 
                new PubKeyCredParam(COSE.Algorithm.RS256)
            },
            options: new AuthenticatorMakeCredentialOptions { ResidentKey = true }                
        );
        
        string expect = @"
01                                      # authenticatorMakeCredential command
a5                                      # map(5)
   01                                   # unsigned(1) - clientDataHash
   58 20                                # bytes(32)
      687134968222ec17202e42505f8ed2b1  # h’687134968222ec17202e42505f8ed2b16ae22f16bb05b88c25db9e602645f141'
      6ae22f16bb05b88c25db9e602645f141  #
   02                                   # unsigned(2) - rp
   a2                                   # map(2)
      62                                # text(2)
         6964                           # ""id""
      6b                                # text(11)
         6578616d706c652e636f6d         # ""example.com""
      64                                # text(4)
         6e616d65                       # ""name""
      64                                # text(4)
         41636d65                       # ""Acme""
   03                                   # unsigned(3) - user
   a4                                   # map(4)
      62                                # text(2)
         6964                           # ""id""
      58 20                             # bytes(32)
         3082019330820138a003020102     # userid
         3082019330820138a003020102     # ...
         308201933082                   # ...
      64                                # text(4)
         69636f6e                       # ""icon""
      78 2b                             # text(43)
         68747470733a2f2f706963732e6578 # ""https://pics.example.com/00/p/aBjjjpqPb.png""
         616d706c652e636f6d2f30302f702f #
         61426a6a6a707150622e706e67     #
      64                                # text(4)
         6e616d65                       # ""name""
      76                                # text(22)
         6a6f686e70736d697468406578616d # ""johnpsmith@example.com""
         706c652e636f6d                 # ...
      6b                                # text(11)
         646973706c61794e616d65         # ""displayName""
      6d                                # text(13)
         4a6f686e20502e20536d697468     # ""John P. Smith""
   04                                   # unsigned(4) - pubKeyCredParams
   82                                   # array(2)
      a2                                # map(2)
         63                             # text(3)
            616c67                      # ""alg""
         26                             # -7 (ES256)
         64                             # text(4)
            74797065                    # ""type""
         6a                             # text(10)
            7075626C69632D6B6579        # ""public-key""
      a2                                # map(2)
         63                             # text(3)
            616c67                      # ""alg""
         390100                         # -257 (RS256)
         64                             # text(4)
            74797065                    # ""type""
         6a                             # text(10)
            7075626C69632D6B6579        # ""public-key""
   07                                   # unsigned(7) - options
   a1                                   # map(1)
      62                                # text(2)
         726b                           # ""rk""
      f5                                # primitive(21)
";


        Assert.Equal(TestHelper.GetCborEncodedHexString(expect).ToLower(), Convert.ToHexString(request.GetPayload()).ToLower());
    }
}
