using Fido2NetLib.Ctap2;

public abstract class AuthenticatorBase
{
    public async ValueTask<AuthenticatorMakeCredentialResponse> MakeCredentialAsync(AuthenticatorMakeCredentialCommand command)
    {
        var result = await ExecuteCommandAsync(command);

        result.CheckStatus();

        return AuthenticatorMakeCredentialResponse.FromCborObject(result.GetCborObject());
    }

    public async ValueTask<AuthenticatorGetAssertionResponse> GetAssertionAsync(AuthenticatorGetAssertionCommand command)
    {
        var result = await ExecuteCommandAsync(command);

        result.CheckStatus();

        return AuthenticatorGetAssertionResponse.FromCborObject(result.GetCborObject());
    }

    public async ValueTask<AuthenticatorGetInfoResponse> GetInfoAsync()
    {
        var result = await ExecuteCommandAsync(new AuthenticatorGetInfoCommand());

        result.CheckStatus();

        return AuthenticatorGetInfoResponse.FromCborObject(result.GetCborObject());
    }
     

    public async ValueTask<AuthenticatorClientPinResponse> ExecuteClientPinCommand(AuthenticatorClientPinCommand command)
    {
        var result = await ExecuteCommandAsync(command);

        result.CheckStatus();

        return AuthenticatorClientPinResponse.FromCborObject(result.GetCborObject());
    }

    public async ValueTask<AuthenticatorResetResponse> ResetAsync()
    {
        var result = await ExecuteCommandAsync(new AuthenticatorResetCommand());

        result.CheckStatus();

        return new AuthenticatorResetResponse();
    }

    public async ValueTask<AuthenticatorGetNextAssertionResponse> GetNextAssertionAsync()
    {
        var result = await ExecuteCommandAsync(new AuthenticatorGetNextAssertionCommand());

        result.CheckStatus();

        return AuthenticatorGetNextAssertionResponse.FromCborObject(result.GetCborObject());
    }

    protected abstract ValueTask<FidoDeviceResponse> ExecuteCommandAsync(CtapCommand command);
}
