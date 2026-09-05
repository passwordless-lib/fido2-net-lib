using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorLargeBlobsCommandTests
{
    private static CborMap DecodePayload(byte[] payload)
    {
        Assert.Equal((byte)CtapCommandType.AuthenticatorLargeBlobs, payload[0]);

        return (CborMap)CborObject.Decode(payload.AsMemory(1));
    }

    [Fact]
    public void GetPayload_ReadRequest_EncodesGetAndOffset()
    {
        var command = new AuthenticatorLargeBlobsCommand(offset: 0, get: 960);

        var map = DecodePayload(command.GetPayload());

        Assert.Equal(2, map.Count);
        Assert.Equal(960, (int)map.Single(kvp => (int)kvp.Key == 0x01).Value);
        Assert.Equal(0, (int)map.Single(kvp => (int)kvp.Key == 0x03).Value);
    }

    [Fact]
    public void GetPayload_InitialWriteRequest_EncodesSetLengthAndOffset()
    {
        byte[] fragment = [1, 2, 3, 4];

        var command = new AuthenticatorLargeBlobsCommand(offset: 0, set: fragment, length: 100);

        var map = DecodePayload(command.GetPayload());

        Assert.Equal(fragment, (byte[])map.Single(kvp => (int)kvp.Key == 0x02).Value);
        Assert.Equal(0, (int)map.Single(kvp => (int)kvp.Key == 0x03).Value);
        Assert.Equal(100, (int)map.Single(kvp => (int)kvp.Key == 0x04).Value);
    }

    [Fact]
    public void GetPayload_SubsequentWriteRequest_OmitsLength()
    {
        byte[] fragment = [5, 6, 7];
        byte[] pinUvAuthParam = Convert.FromHexString("00112233445566778899aabbccddeeff");

        var command = new AuthenticatorLargeBlobsCommand(
            offset: 100,
            set: fragment,
            pinUvAuthParam: pinUvAuthParam,
            pinUvAuthProtocol: 1);

        var map = DecodePayload(command.GetPayload());

        Assert.DoesNotContain(map, kvp => (int)kvp.Key == 0x04);
        Assert.Equal(100, (int)map.Single(kvp => (int)kvp.Key == 0x03).Value);
        Assert.Equal(pinUvAuthParam, (byte[])map.Single(kvp => (int)kvp.Key == 0x05).Value);
        Assert.Equal(1, (int)map.Single(kvp => (int)kvp.Key == 0x06).Value);
    }
}
