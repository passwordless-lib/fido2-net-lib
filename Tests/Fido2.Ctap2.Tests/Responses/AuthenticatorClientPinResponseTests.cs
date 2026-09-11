namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorClientPinResponseTests
{
    [Fact]
    public void Deserialize()
    {
        string hexEncodedCborData = """

            00                                      # status = success
            a5                                      # map(5)
               01                                   # 0x01 keyAgreement (COSE EC2/ES256)
               a50102032620012158207725bd245388113ed99552358ddf50b1ced4b71932baebd14cf8a136b00868f922582045d945825544581dc4bf360baa17c923b15eb0f334afb8d7c47137d818fe82be
               02                                   # 0x02 pinUvAuthToken
               5011111111111111111111111111111111
               03 06                                # 0x03 pinRetries = 6
               04 f5                                # 0x04 powerCycleState = true
               05 04                                # 0x05 uvRetries = 4
            """;

        var response = AuthenticatorClientPinResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.NotNull(response.KeyAgreement);
        Assert.Equal(16, response.PinUvAuthToken!.Length);
        Assert.Equal(6, response.PinRetries);
        Assert.True(response.PowerCycleState);
        Assert.Equal(4, response.UVRetries);
    }
}
