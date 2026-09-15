using System.Security.Cryptography;

using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2.Tests;

public class FidoAuthenticatorBioEnrollmentTests
{
    private sealed class RecordingAuthenticator : FidoAuthenticator
    {
        public CtapCommand? LastCommand { get; private set; }

        protected override ValueTask<FidoAuthenticatorResponse> ExecuteCommandAsync(CtapCommand command)
        {
            LastCommand = command;

            return ValueTask.FromResult(new FidoAuthenticatorResponse(CtapStatusCode.OK));
        }
    }

    private static byte[] ExpectedPinUvAuthParam(byte[] pinUvAuthToken, AuthenticatorBioEnrollmentSubCommand subCommand, byte[] encodedSubCommandParams)
    {
        var message = new byte[2 + encodedSubCommandParams.Length];
        message[0] = (byte)AuthenticatorBioEnrollmentModality.Fingerprint;
        message[1] = (byte)subCommand;
        encodedSubCommandParams.CopyTo(message.AsSpan(2));

        return HMACSHA256.HashData(pinUvAuthToken, message).AsSpan(0, 16).ToArray();
    }

    [Fact]
    public async Task EnrollFingerprintBeginAsync_WithNoTimeout_OmitsSubCommandParams()
    {
        var authenticator = new RecordingAuthenticator();
        var pinUvAuthToken = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");

        await authenticator.EnrollFingerprintBeginAsync(pinUvAuthToken);

        var command = Assert.IsType<AuthenticatorBioEnrollmentCommand>(authenticator.LastCommand);

        Assert.Equal(AuthenticatorBioEnrollmentModality.Fingerprint, command.Modality);
        Assert.Equal(AuthenticatorBioEnrollmentSubCommand.EnrollBegin, command.SubCommand);
        Assert.Null(command.SubCommandParams);
        Assert.Equal(
            ExpectedPinUvAuthParam(pinUvAuthToken, AuthenticatorBioEnrollmentSubCommand.EnrollBegin, []),
            command.PinUvAuthParam);
    }

    [Fact]
    public async Task EnrollFingerprintCaptureNextSampleAsync_IncludesTemplateIdInAuthParam()
    {
        var authenticator = new RecordingAuthenticator();
        var pinUvAuthToken = Convert.FromHexString("ffeeddccbbaa99887766554433221100");
        byte[] templateId = [1, 2, 3, 4];

        await authenticator.EnrollFingerprintCaptureNextSampleAsync(templateId, pinUvAuthToken);

        var command = Assert.IsType<AuthenticatorBioEnrollmentCommand>(authenticator.LastCommand);

        Assert.NotNull(command.SubCommandParams);

        var expected = ExpectedPinUvAuthParam(
            pinUvAuthToken,
            AuthenticatorBioEnrollmentSubCommand.EnrollCaptureNextSample,
            command.SubCommandParams!.Encode());

        Assert.Equal(expected, command.PinUvAuthParam);
    }

    [Fact]
    public async Task CancelCurrentEnrollmentAsync_SendsUnauthenticatedCommand()
    {
        var authenticator = new RecordingAuthenticator();

        await authenticator.CancelCurrentEnrollmentAsync();

        var command = Assert.IsType<AuthenticatorBioEnrollmentCommand>(authenticator.LastCommand);

        Assert.Equal(AuthenticatorBioEnrollmentSubCommand.CancelCurrentEnrollment, command.SubCommand);
        Assert.Null(command.PinUvAuthParam);
    }

    [Fact]
    public async Task SetFingerprintFriendlyNameAsync_ComputesExpectedPinUvAuthParam()
    {
        var authenticator = new RecordingAuthenticator();
        var pinUvAuthToken = Convert.FromHexString("11223344556677889900aabbccddeeff");
        byte[] templateId = [9, 9, 9];

        await authenticator.SetFingerprintFriendlyNameAsync(templateId, "Right thumb", pinUvAuthToken);

        var command = Assert.IsType<AuthenticatorBioEnrollmentCommand>(authenticator.LastCommand);

        var expected = ExpectedPinUvAuthParam(
            pinUvAuthToken,
            AuthenticatorBioEnrollmentSubCommand.SetFriendlyName,
            command.SubCommandParams!.Encode());

        Assert.Equal(expected, command.PinUvAuthParam);
    }
}
