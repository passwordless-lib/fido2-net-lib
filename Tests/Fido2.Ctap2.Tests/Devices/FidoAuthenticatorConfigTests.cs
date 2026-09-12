using System.Security.Cryptography;

using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2.Tests;

public class FidoAuthenticatorConfigTests
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

    private static byte[] ExpectedPinUvAuthParam(byte[] pinUvAuthToken, AuthenticatorConfigSubCommand subCommand, byte[] encodedSubCommandParams)
    {
        var message = new byte[34 + encodedSubCommandParams.Length];
        message.AsSpan(0, 32).Fill(0xff);
        message[32] = (byte)CtapCommandType.AuthenticatorConfig;
        message[33] = (byte)subCommand;
        encodedSubCommandParams.CopyTo(message.AsSpan(34));

        return HMACSHA256.HashData(pinUvAuthToken, message).AsSpan(0, 16).ToArray();
    }

    [Fact]
    public async Task ToggleAlwaysUvAsync_ComputesExpectedPinUvAuthParam()
    {
        var authenticator = new RecordingAuthenticator();
        var pinUvAuthToken = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");

        await authenticator.ToggleAlwaysUvAsync(pinUvAuthToken);

        var command = Assert.IsType<AuthenticatorConfigCommand>(authenticator.LastCommand);

        Assert.Equal(AuthenticatorConfigSubCommand.ToggleAlwaysUv, command.SubCommand);
        Assert.Null(command.SubCommandParams);
        Assert.Equal(1u, command.PinUvAuthProtocol);
        Assert.Equal(ExpectedPinUvAuthParam(pinUvAuthToken, AuthenticatorConfigSubCommand.ToggleAlwaysUv, []), command.PinUvAuthParam);
    }

    [Fact]
    public async Task ToggleAlwaysUvAsync_WithProtocolTwo_Computes32ByteUntruncatedPinUvAuthParam()
    {
        var authenticator = new RecordingAuthenticator();
        // Protocol two pinUvAuthTokens are exactly 32 bytes.
        var pinUvAuthToken = Convert.FromHexString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e");

        await authenticator.ToggleAlwaysUvAsync(pinUvAuthToken, pinUvAuthProtocol: 2);

        var command = Assert.IsType<AuthenticatorConfigCommand>(authenticator.LastCommand);

        Assert.Equal(2u, command.PinUvAuthProtocol);

        var message = new byte[34];
        message.AsSpan(0, 32).Fill(0xff);
        message[32] = (byte)CtapCommandType.AuthenticatorConfig;
        message[33] = (byte)AuthenticatorConfigSubCommand.ToggleAlwaysUv;
        var expected = HMACSHA256.HashData(pinUvAuthToken, message);

        Assert.Equal(32, command.PinUvAuthParam!.Length);
        Assert.Equal(expected, command.PinUvAuthParam);
    }

    [Fact]
    public async Task EnableEnterpriseAttestationAsync_ComputesExpectedPinUvAuthParam()
    {
        var authenticator = new RecordingAuthenticator();
        var pinUvAuthToken = Convert.FromHexString("ffeeddccbbaa99887766554433221100");

        await authenticator.EnableEnterpriseAttestationAsync(pinUvAuthToken);

        var command = Assert.IsType<AuthenticatorConfigCommand>(authenticator.LastCommand);

        Assert.Equal(AuthenticatorConfigSubCommand.EnableEnterpriseAttestation, command.SubCommand);
        Assert.Equal(ExpectedPinUvAuthParam(pinUvAuthToken, AuthenticatorConfigSubCommand.EnableEnterpriseAttestation, []), command.PinUvAuthParam);
    }

    [Fact]
    public async Task SetMinPinLengthAsync_IncludesSubCommandParamsInAuthParam()
    {
        var authenticator = new RecordingAuthenticator();
        var pinUvAuthToken = Convert.FromHexString("aabbccddeeff00112233445566778899");

        await authenticator.SetMinPinLengthAsync(
            newMinPinLength: 6,
            minPinLengthRpIds: ["example.com"],
            forceChangePin: true,
            pinUvAuthToken: pinUvAuthToken);

        var command = Assert.IsType<AuthenticatorConfigCommand>(authenticator.LastCommand);

        Assert.Equal(AuthenticatorConfigSubCommand.SetMinPinLength, command.SubCommand);
        Assert.NotNull(command.SubCommandParams);

        var expectedParam = ExpectedPinUvAuthParam(
            pinUvAuthToken,
            AuthenticatorConfigSubCommand.SetMinPinLength,
            command.SubCommandParams!.Encode());

        Assert.Equal(expectedParam, command.PinUvAuthParam);
    }

    [Fact]
    public async Task SetMinPinLengthAsync_WithNoParameters_OmitsSubCommandParams()
    {
        var authenticator = new RecordingAuthenticator();
        var pinUvAuthToken = Convert.FromHexString("11223344556677889900aabbccddeeff");

        await authenticator.SetMinPinLengthAsync(
            newMinPinLength: null,
            minPinLengthRpIds: null,
            forceChangePin: null,
            pinUvAuthToken: pinUvAuthToken);

        var command = Assert.IsType<AuthenticatorConfigCommand>(authenticator.LastCommand);

        Assert.Null(command.SubCommandParams);
        Assert.Equal(ExpectedPinUvAuthParam(pinUvAuthToken, AuthenticatorConfigSubCommand.SetMinPinLength, []), command.PinUvAuthParam);
    }

    [Fact]
    public async Task SetMinPinLengthAsync_WithPinComplexityPolicy_IncludesItInSubCommandParams()
    {
        var authenticator = new RecordingAuthenticator();
        var pinUvAuthToken = Convert.FromHexString("223344556677889900112233445566778899");

        await authenticator.SetMinPinLengthAsync(
            newMinPinLength: null,
            minPinLengthRpIds: null,
            forceChangePin: null,
            pinUvAuthToken: pinUvAuthToken,
            pinComplexityPolicy: true);

        var command = Assert.IsType<AuthenticatorConfigCommand>(authenticator.LastCommand);

        Assert.NotNull(command.SubCommandParams);

        var member = Assert.Single(command.SubCommandParams!, kvp => (int)kvp.Key == 0x04);
        Assert.True((bool)(CborBoolean)member.Value);

        var expectedParam = ExpectedPinUvAuthParam(
            pinUvAuthToken,
            AuthenticatorConfigSubCommand.SetMinPinLength,
            command.SubCommandParams!.Encode());

        Assert.Equal(expectedParam, command.PinUvAuthParam);
    }

    [Fact]
    public async Task EnableLongTouchForResetAsync_ComputesExpectedPinUvAuthParam()
    {
        var authenticator = new RecordingAuthenticator();
        var pinUvAuthToken = Convert.FromHexString("0011223344556677889900aabbccddee");

        await authenticator.EnableLongTouchForResetAsync(pinUvAuthToken);

        var command = Assert.IsType<AuthenticatorConfigCommand>(authenticator.LastCommand);

        Assert.Equal(AuthenticatorConfigSubCommand.EnableLongTouchForReset, command.SubCommand);
        Assert.Null(command.SubCommandParams);
        Assert.Equal(ExpectedPinUvAuthParam(pinUvAuthToken, AuthenticatorConfigSubCommand.EnableLongTouchForReset, []), command.PinUvAuthParam);
    }
}
