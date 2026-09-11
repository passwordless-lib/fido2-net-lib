using Fido2NetLib.Ctap2.Exceptions;

namespace Fido2NetLib.Ctap2.Tests;

public class FidoAuthenticatorGetNextAssertionTests
{
    private sealed class RecordingAuthenticator(FidoAuthenticatorResponse response) : FidoAuthenticator
    {
        public CtapCommand? LastCommand { get; private set; }

        protected override ValueTask<FidoAuthenticatorResponse> ExecuteCommandAsync(CtapCommand command)
        {
            LastCommand = command;

            return ValueTask.FromResult(response);
        }
    }

    [Fact]
    public async Task GetNextAssertionAsync_SendsCommandAndDecodesResponse()
    {
        string hexEncodedCborData = """

            00                                      # status = success
            a2                                      # map(2)
               02                                   # unsigned(2) - authData
               43                                   # bytes(3)
                  010203                            # ...
               03                                   # unsigned(3) - signature
               44                                   # bytes(4)
                  04050607                          # ...
            """;

        var authenticator = new RecordingAuthenticator(TestHelper.GetResponse(hexEncodedCborData));

        var response = await authenticator.GetNextAssertionAsync();

        var command = Assert.IsType<AuthenticatorGetNextAssertionCommand>(authenticator.LastCommand);
        Assert.Equal((byte)CtapCommandType.AuthenticatorGetNextAssertion, command.GetPayload()[0]);
        Assert.Single(command.GetPayload());

        Assert.Null(response.Credential);
        Assert.Equal(3, response.AuthData.Length);
        Assert.Equal(4, response.Signature.Length);
    }

    [Fact]
    public async Task GetNextAssertionAsync_ThrowsOnErrorStatus()
    {
        var authenticator = new RecordingAuthenticator(new FidoAuthenticatorResponse(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED));

        await Assert.ThrowsAsync<CtapException>(() => authenticator.GetNextAssertionAsync().AsTask());
    }
}
