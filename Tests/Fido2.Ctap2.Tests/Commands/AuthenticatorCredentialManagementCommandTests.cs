using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorCredentialManagementCommandTests
{
    private static CborMap DecodePayload(byte[] payload)
    {
        Assert.Equal((byte)CtapCommandType.AuthenticatorCredentialManagement, payload[0]);

        return (CborMap)CborObject.Decode(payload.AsMemory(1));
    }

    [Fact]
    public void GetPayload_GetCredsMetadata_EncodesSubCommandAndAuthParams()
    {
        var pinUvAuthParam = Convert.FromHexString("0102030405060708090a0b0c0d0e0f10");

        var command = new AuthenticatorCredentialManagementCommand(
            AuthenticatorCredentialManagementSubCommand.GetCredsMetadata,
            pinUvAuthProtocol: 1,
            pinUvAuthParam: pinUvAuthParam);

        var map = DecodePayload(command.GetPayload());

        Assert.Equal(3, map.Count);

        foreach (var (key, value) in map)
        {
            switch ((int)key)
            {
                case 0x01:
                    Assert.Equal((int)AuthenticatorCredentialManagementSubCommand.GetCredsMetadata, (int)value);
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
    public void GetPayload_EnumerateCredentialsBegin_EncodesRpIdHashInSubCommandParams()
    {
        var rpIdHash = Convert.FromHexString("00112233445566778899aabbccddeeff00112233445566778899aabbccddee");

        var subCommandParams = new CborMap { { 0x01, rpIdHash } };

        var command = new AuthenticatorCredentialManagementCommand(
            AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsBegin,
            subCommandParams: subCommandParams,
            pinUvAuthProtocol: 1,
            pinUvAuthParam: Convert.FromHexString("00112233445566778899aabbccddeeff"));

        var map = DecodePayload(command.GetPayload());

        var decodedParams = (CborMap)map.Single(kvp => (int)kvp.Key == 0x02).Value;

        Assert.Equal(rpIdHash, (byte[])decodedParams.Single(kvp => (int)kvp.Key == 0x01).Value);
    }

    [Fact]
    public void GetPayload_NoOptionalMembers_OmitsThem()
    {
        var command = new AuthenticatorCredentialManagementCommand(AuthenticatorCredentialManagementSubCommand.EnumerateRPsGetNextRP);

        var map = DecodePayload(command.GetPayload());

        Assert.Single(map);
    }
}
