using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorCredentialManagementResponseTests
{
    [Fact]
    public void DeserializeCredsMetadata()
    {
        // Shape returned by getCredsMetadata.
        string hexEncodedCborData = """

            00                                      # status = success
            a2                                      # map(2)
               01 05                                # 0x01 existingResidentCredentialsCount = 5
               02 14                                # 0x02 maxPossibleRemainingResidentCredentialsCount = 20
            """;

        var response = AuthenticatorCredentialManagementResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Equal(5, response.ExistingResidentCredentialsCount);
        Assert.Equal(20, response.MaxPossibleRemainingResidentCredentialsCount);
    }

    [Fact]
    public void DeserializeEnumerateRps()
    {
        // Shape returned by enumerateRPsBegin/enumerateRPsGetNextRP.
        string hexEncodedCborData = """

            00                                      # status = success
            a3                                      # map(3)
               03                                   # 0x03 rp
               a2 6269646b6578616d706c652e636f6d646e616d656a4578616d706c652052 50
               04                                   # 0x04 rpIDHash
               5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
               05 03                                # 0x05 totalRPs = 3
            """;

        var response = AuthenticatorCredentialManagementResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Equal("example.com", response.Rp!.Id);
        Assert.Equal("Example RP", response.Rp.Name);
        Assert.Equal(32, response.RpIdHash!.Length);
        Assert.Equal(3, response.TotalRPs);
    }

    [Fact]
    public void DeserializeEnumerateCredentials()
    {
        // Shape returned by enumerateCredentialsBegin/enumerateCredentialsGetNextCredential.
        string hexEncodedCborData = """

            00                                      # status = success
            a7                                      # map(7)
               06                                   # 0x06 user
               a3626964420102646e616d657075736572406578616d706c652e636f6d6b646973706c61794e616d656c4578616d706c652055736572
               07                                   # 0x07 credentialID
               a262696442f1d064747970656a7075626c69632d6b6579
               08                                   # 0x08 publicKey (COSE EC2/ES256)
               a50102032620012158207725bd245388113ed99552358ddf50b1ced4b71932baebd14cf8a136b00868f922582045d945825544581dc4bf360baa17c923b15eb0f334afb8d7c47137d818fe82be
               09 07                                # 0x09 totalCredentials = 7
               0a 03                                # 0x0A credProtect = 3
               0b 44cccccccc                        # 0x0B largeBlobKey
               0c f5                                # 0x0C thirdPartyPayment = true
            """;

        var response = AuthenticatorCredentialManagementResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Equal("user@example.com", response.User!.Name);
        Assert.Equal("Example User", response.User.DisplayName);
        Assert.Equal("f1d0", Convert.ToHexString(response.CredentialId!.Id).ToLower());
        Assert.Equal(PublicKeyCredentialType.PublicKey, response.CredentialId.Type);
        Assert.NotNull(response.PublicKey);
        Assert.True(response.PublicKey!.IsSameAlg(COSE.Algorithm.ES256));
        Assert.Equal(7, response.TotalCredentials);
        Assert.Equal(3, response.CredProtect);
        Assert.Equal("cccccccc", Convert.ToHexString(response.LargeBlobKey!).ToLower());
        Assert.True(response.ThirdPartyPayment);
    }
}
