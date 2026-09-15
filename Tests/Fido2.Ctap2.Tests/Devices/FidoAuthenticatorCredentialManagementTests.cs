using System.Security.Cryptography;

using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class FidoAuthenticatorCredentialManagementTests
{
    private sealed class ScriptedAuthenticator : FidoAuthenticator
    {
        private readonly Queue<CborMap> _responses;

        public ScriptedAuthenticator(params CborMap[] responses)
        {
            _responses = new Queue<CborMap>(responses);
        }

        public List<CtapCommand> Commands { get; } = [];

        protected override ValueTask<FidoAuthenticatorResponse> ExecuteCommandAsync(CtapCommand command)
        {
            Commands.Add(command);

            var payload = _responses.Dequeue();

            var message = new byte[1 + payload.Encode().Length];
            message[0] = (byte)CtapStatusCode.OK;
            payload.Encode().CopyTo(message.AsSpan(1));

            return ValueTask.FromResult(new FidoAuthenticatorResponse(message));
        }
    }

    private static byte[] ExpectedPinUvAuthParam(byte[] pinUvAuthToken, AuthenticatorCredentialManagementSubCommand subCommand, byte[] encodedSubCommandParams)
    {
        var message = new byte[1 + encodedSubCommandParams.Length];
        message[0] = (byte)subCommand;
        encodedSubCommandParams.CopyTo(message.AsSpan(1));

        return HMACSHA256.HashData(pinUvAuthToken, message).AsSpan(0, 16).ToArray();
    }

    [Fact]
    public async Task GetCredsMetadataAsync_ComputesExpectedPinUvAuthParam()
    {
        var authenticator = new ScriptedAuthenticator(new CborMap { { 0x01, 3 }, { 0x02, 17 } });
        var pinUvAuthToken = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");

        var result = await authenticator.GetCredsMetadataAsync(pinUvAuthToken);

        var command = Assert.IsType<AuthenticatorCredentialManagementCommand>(Assert.Single(authenticator.Commands));

        Assert.Equal(AuthenticatorCredentialManagementSubCommand.GetCredsMetadata, command.SubCommand);
        Assert.Null(command.SubCommandParams);
        Assert.Equal(
            ExpectedPinUvAuthParam(pinUvAuthToken, AuthenticatorCredentialManagementSubCommand.GetCredsMetadata, []),
            command.PinUvAuthParam);

        Assert.Equal(3, result.ExistingResidentCredentialsCount);
        Assert.Equal(17, result.MaxPossibleRemainingResidentCredentialsCount);
    }

    [Fact]
    public async Task DeleteCredentialAsync_IncludesCredentialIdInAuthParam()
    {
        var authenticator = new ScriptedAuthenticator(new CborMap());
        var pinUvAuthToken = Convert.FromHexString("ffeeddccbbaa99887766554433221100");
        var credentialId = new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PublicKey, [0x01, 0x02, 0x03], null);

        await authenticator.DeleteCredentialAsync(credentialId, pinUvAuthToken);

        var command = Assert.IsType<AuthenticatorCredentialManagementCommand>(Assert.Single(authenticator.Commands));

        Assert.Equal(AuthenticatorCredentialManagementSubCommand.DeleteCredential, command.SubCommand);
        Assert.NotNull(command.SubCommandParams);

        var expected = ExpectedPinUvAuthParam(
            pinUvAuthToken,
            AuthenticatorCredentialManagementSubCommand.DeleteCredential,
            command.SubCommandParams!.Encode());

        Assert.Equal(expected, command.PinUvAuthParam);
    }

    [Fact]
    public async Task EnumerateRPsAsync_StopsAfterTotalRPs()
    {
        var rp1 = new CborMap { { "id", "example.com" }, { "name", "Example" } };
        var rp2 = new CborMap { { "id", "other.example" }, { "name", "Other" } };

        var authenticator = new ScriptedAuthenticator(
            new CborMap { { 0x03, rp1 }, { 0x04, new byte[32] }, { 0x05, 2 } },
            new CborMap { { 0x03, rp2 }, { 0x04, new byte[32] } });

        var pinUvAuthToken = Convert.FromHexString("aabbccddeeff00112233445566778899");

        var results = await authenticator.EnumerateRPsAsync(pinUvAuthToken);

        Assert.Equal(2, results.Count);
        Assert.Equal(2, authenticator.Commands.Count);

        var beginCommand = Assert.IsType<AuthenticatorCredentialManagementCommand>(authenticator.Commands[0]);
        Assert.Equal(AuthenticatorCredentialManagementSubCommand.EnumerateRPsBegin, beginCommand.SubCommand);

        var nextCommand = Assert.IsType<AuthenticatorCredentialManagementCommand>(authenticator.Commands[1]);
        Assert.Equal(AuthenticatorCredentialManagementSubCommand.EnumerateRPsGetNextRP, nextCommand.SubCommand);
        Assert.Null(nextCommand.PinUvAuthParam);

        Assert.Equal("example.com", results[0].Rp!.Id);
        Assert.Equal("other.example", results[1].Rp!.Id);
    }

    [Fact]
    public async Task EnumerateRPsAsync_SingleRP_IssuesOnlyBeginCommand()
    {
        var rp = new CborMap { { "id", "example.com" }, { "name", "Example" } };

        var authenticator = new ScriptedAuthenticator(
            new CborMap { { 0x03, rp }, { 0x04, new byte[32] }, { 0x05, 1 } });

        var pinUvAuthToken = Convert.FromHexString("aabbccddeeff00112233445566778899");

        var results = await authenticator.EnumerateRPsAsync(pinUvAuthToken);

        Assert.Single(results);
        Assert.Single(authenticator.Commands);
    }
}
