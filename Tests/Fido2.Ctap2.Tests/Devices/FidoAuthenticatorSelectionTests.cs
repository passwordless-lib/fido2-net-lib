namespace Fido2NetLib.Ctap2.Tests;

public class FidoAuthenticatorSelectionTests
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

    [Fact]
    public async Task SelectAsync_SendsAuthenticatorSelectionCommand()
    {
        var authenticator = new RecordingAuthenticator();

        await authenticator.SelectAsync();

        var command = Assert.IsType<AuthenticatorSelectionCommand>(authenticator.LastCommand);
        Assert.Equal((byte)CtapCommandType.AuthenticatorSelection, command.GetPayload()[0]);
        Assert.Single(command.GetPayload());
    }
}
