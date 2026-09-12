using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorConfigCommandTests
{
    private static CborMap DecodePayload(byte[] payload)
    {
        Assert.Equal((byte)CtapCommandType.AuthenticatorConfig, payload[0]);

        return (CborMap)CborObject.Decode(payload.AsMemory(1));
    }

    [Fact]
    public void GetPayload_EnableEnterpriseAttestation_EncodesSubCommandAndAuthParams()
    {
        var pinUvAuthParam = Convert.FromHexString("0102030405060708090a0b0c0d0e0f10");

        var command = new AuthenticatorConfigCommand(
            AuthenticatorConfigSubCommand.EnableEnterpriseAttestation,
            pinUvAuthProtocol: 1,
            pinUvAuthParam: pinUvAuthParam);

        var map = DecodePayload(command.GetPayload());

        Assert.Equal(3, map.Count);

        foreach (var (key, value) in map)
        {
            switch ((int)key)
            {
                case 0x01:
                    Assert.Equal((int)AuthenticatorConfigSubCommand.EnableEnterpriseAttestation, (int)value);
                    break;
                case 0x03:
                    Assert.Equal(1, (int)value);
                    break;
                case 0x04:
                    Assert.Equal(pinUvAuthParam, (byte[])value);
                    break;
                default:
                    Assert.Fail($"Unexpected member key {key}");
                    break;
            }
        }
    }

    [Fact]
    public void GetPayload_SetMinPinLength_EncodesSubCommandParams()
    {
        var subCommandParams = new CborMap
        {
            { 0x01, 6 },
            { 0x03, (CborObject)(CborBoolean)true }
        };

        var command = new AuthenticatorConfigCommand(
            AuthenticatorConfigSubCommand.SetMinPinLength,
            subCommandParams: subCommandParams,
            pinUvAuthProtocol: 1,
            pinUvAuthParam: Convert.FromHexString("00112233445566778899aabbccddeeff"));

        var map = DecodePayload(command.GetPayload());

        var decodedParams = (CborMap)map.Single(kvp => (int)kvp.Key == 0x02).Value;

        Assert.Equal(6, (int)decodedParams.Single(kvp => (int)kvp.Key == 0x01).Value);
        Assert.True((bool)(CborBoolean)decodedParams.Single(kvp => (int)kvp.Key == 0x03).Value);
    }

    [Fact]
    public void GetPayload_NoOptionalMembers_OmitsThem()
    {
        var command = new AuthenticatorConfigCommand(AuthenticatorConfigSubCommand.ToggleAlwaysUv);

        var map = DecodePayload(command.GetPayload());

        Assert.Single(map);
    }
}
