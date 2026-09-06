using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorBioEnrollmentCommandTests
{
    private static CborMap DecodePayload(byte[] payload)
    {
        Assert.Equal((byte)CtapCommandType.AuthenticatorBioEnrollment, payload[0]);

        return (CborMap)CborObject.Decode(payload.AsMemory(1));
    }

    [Fact]
    public void GetPayload_GetModality_EncodesOnlyGetModalityMember()
    {
        var command = new AuthenticatorBioEnrollmentCommand(getModality: true);

        var map = DecodePayload(command.GetPayload());

        Assert.Single(map);
        Assert.True((bool)map.Single(kvp => (int)kvp.Key == 0x06).Value);
    }

    [Fact]
    public void GetPayload_EnrollBegin_EncodesModalitySubCommandAndAuthParams()
    {
        var pinUvAuthParam = Convert.FromHexString("0102030405060708090a0b0c0d0e0f10");

        var command = new AuthenticatorBioEnrollmentCommand(
            AuthenticatorBioEnrollmentModality.Fingerprint,
            AuthenticatorBioEnrollmentSubCommand.EnrollBegin,
            pinUvAuthProtocol: 1,
            pinUvAuthParam: pinUvAuthParam);

        var map = DecodePayload(command.GetPayload());

        Assert.Equal((int)AuthenticatorBioEnrollmentModality.Fingerprint, (int)map.Single(kvp => (int)kvp.Key == 0x01).Value);
        Assert.Equal((int)AuthenticatorBioEnrollmentSubCommand.EnrollBegin, (int)map.Single(kvp => (int)kvp.Key == 0x02).Value);
        Assert.Equal(1, (int)map.Single(kvp => (int)kvp.Key == 0x04).Value);
        Assert.Equal(pinUvAuthParam, (byte[])map.Single(kvp => (int)kvp.Key == 0x05).Value);
    }

    [Fact]
    public void GetPayload_RemoveEnrollment_EncodesTemplateIdInSubCommandParams()
    {
        byte[] templateId = [0xAA, 0xBB, 0xCC];

        var subCommandParams = new CborMap { { 0x01, templateId } };

        var command = new AuthenticatorBioEnrollmentCommand(
            AuthenticatorBioEnrollmentModality.Fingerprint,
            AuthenticatorBioEnrollmentSubCommand.RemoveEnrollment,
            subCommandParams: subCommandParams,
            pinUvAuthProtocol: 1,
            pinUvAuthParam: Convert.FromHexString("00112233445566778899aabbccddeeff"));

        var map = DecodePayload(command.GetPayload());

        var decodedParams = (CborMap)map.Single(kvp => (int)kvp.Key == 0x03).Value;

        Assert.Equal(templateId, (byte[])decodedParams.Single(kvp => (int)kvp.Key == 0x01).Value);
    }
}
