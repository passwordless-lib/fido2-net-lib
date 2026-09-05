using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorClientPinCommandPermissionsTests
{
    private static CborMap DecodePayload(byte[] payload)
    {
        Assert.Equal((byte)CtapCommandType.AuthenticatorClientPin, payload[0]);

        return (CborMap)CborObject.Decode(payload.AsMemory(1));
    }

    [Theory]
    [InlineData(PinUvAuthTokenPermissions.MakeCredential, 0x01)]
    [InlineData(PinUvAuthTokenPermissions.GetAssertion, 0x02)]
    [InlineData(PinUvAuthTokenPermissions.CredentialManagement, 0x04)]
    [InlineData(PinUvAuthTokenPermissions.BioEnrollment, 0x08)]
    [InlineData(PinUvAuthTokenPermissions.LargeBlobWrite, 0x10)]
    [InlineData(PinUvAuthTokenPermissions.AuthenticatorConfiguration, 0x20)]
    [InlineData(PinUvAuthTokenPermissions.PersistentCredentialManagementReadOnly, 0x40)]
    public void PermissionValues_MatchSpecBitAssignments(PinUvAuthTokenPermissions permission, int expected)
    {
        Assert.Equal(expected, (int)permission);
    }

    [Fact]
    public void GetPayload_WithPermissionsAndRpId_EncodesBothMembers()
    {
        var command = new AuthenticatorClientPinCommand(
            pinProtocol: 1,
            subCommand: AuthenticatorClientPinSubCommand.GetPinUvAuthTokenUsingPinWithPermissions,
            pinHashEnc: new byte[16],
            permissions: PinUvAuthTokenPermissions.MakeCredential | PinUvAuthTokenPermissions.GetAssertion,
            rpId: "example.com");

        var map = DecodePayload(command.GetPayload());

        Assert.Equal(0x03, (int)map.Single(kvp => (int)kvp.Key == 0x09).Value);
        Assert.Equal("example.com", (string)map.Single(kvp => (int)kvp.Key == 0x0A).Value);
    }

    [Fact]
    public void GetPayload_WithoutPermissions_OmitsPermissionsAndRpIdMembers()
    {
        var command = new AuthenticatorClientPinCommand(
            pinProtocol: 1,
            subCommand: AuthenticatorClientPinSubCommand.GetPinToken,
            pinHashEnc: new byte[16]);

        var map = DecodePayload(command.GetPayload());

        Assert.DoesNotContain(map, kvp => (int)kvp.Key == 0x09);
        Assert.DoesNotContain(map, kvp => (int)kvp.Key == 0x0A);
    }
}
