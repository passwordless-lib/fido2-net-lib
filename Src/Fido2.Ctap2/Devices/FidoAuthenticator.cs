using System.Security.Cryptography;
using System.Text;

using Fido2NetLib.Ctap2;
using Fido2NetLib.Objects;

public abstract class FidoAuthenticator
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
     

    public async ValueTask<AuthenticatorClientPinResponse> ExecuteClientPinCommandAsync(AuthenticatorClientPinCommand command)
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

    // Helper APIs --

    public async ValueTask<int> GetRetriesAsync()
    {
        var command = new AuthenticatorClientPinCommand(pinProtocol: 0x01, subCommand: AuthenticatorClientPinSubCommand.GetRetries);

        var result = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);

        return result.Retries!.Value;
    }

    public async ValueTask SetNewPinAsync(string newPinUnicode, CredentialPublicKey platformKey, byte[] sharedSecret)
    {
        ArgumentNullException.ThrowIfNull(newPinUnicode);

        var newPin = Encoding.UTF8.GetBytes(newPinUnicode);

        if (newPin.Length < 4)
        {
            throw new ArgumentException("Must be at least 4 bytes", nameof(newPinUnicode));
        }

        // AES256-CBC(sharedSecret, IV=0, newPin).
        byte[] newPinEnc = CryptoHelper.AesCbcDefaultIvNoPadding(sharedSecret, CryptoHelper.ZeroPadRight(newPin, 64));

        // LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
        var pinAuth = HMACSHA256.HashData(sharedSecret, newPinEnc).AsSpan(0, 16).ToArray(); 

        var command = new AuthenticatorClientPinCommand(
            pinProtocol  : 0x01, 
            subCommand   : AuthenticatorClientPinSubCommand.SetPin,
            keyAgreement : platformKey,
            pinAuth      : pinAuth,
            newPinEnc    : newPinEnc
        );

        _ = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);
    }

    public async ValueTask ChangePinAsync(string curPinUnicode, string newPinUnicode, CredentialPublicKey platformKey, byte[] sharedSecret)
    {
        ArgumentNullException.ThrowIfNull(newPinUnicode);

        var curPin = Encoding.UTF8.GetBytes(curPinUnicode);
        var newPin = Encoding.UTF8.GetBytes(newPinUnicode);

        if (newPin.Length < 4)
        {
            throw new ArgumentException("Must be at least 4 bytes", nameof(newPinUnicode));
        }

        // AES256-CBC(sharedSecret, IV=0, LEFT(SHA-256(curPin),16)).
        byte[] pinHashEnc = CryptoHelper.AesCbcDefaultIvNoPadding(sharedSecret, SHA256.HashData(curPin).AsSpan(0, 16));

        // AES256-CBC(sharedSecret, IV=0, newPin).
        byte[] newPinEnc = CryptoHelper.AesCbcDefaultIvNoPadding(sharedSecret, CryptoHelper.ZeroPadRight(newPin, 64));

        // LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
        byte[] pinAuth = HMACSHA256.HashData(sharedSecret, newPinEnc).AsSpan(0, 16).ToArray();

        var command = new AuthenticatorClientPinCommand(
            pinProtocol  : 0x01,
            subCommand   : AuthenticatorClientPinSubCommand.ChangePin,
            keyAgreement : platformKey,
            pinAuth      : pinAuth,
            newPinEnc    : newPinEnc,
            pinHashEnc   : pinHashEnc
        );

        _= await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);
    }

    public async ValueTask<byte[]> GetPinTokenAsync(string pin, CredentialPublicKey platformKey, byte[] sharedSecret)
    {
        ArgumentNullException.ThrowIfNull(pin);

        byte[] curPin = Encoding.UTF8.GetBytes(pin);

        // AES256-CBC(sharedSecret, IV = 0, LEFT(SHA - 256(PIN), 16)).
        byte[] pinHashEnc = CryptoHelper.AesCbcDefaultIvNoPadding(sharedSecret, SHA256.HashData(curPin).AsSpan(0, 16));

        var command = new AuthenticatorClientPinCommand(
            pinProtocol  : 0x01,
            subCommand   : AuthenticatorClientPinSubCommand.GetPinToken,
            keyAgreement : platformKey,
            pinHashEnc   : pinHashEnc
        );

        var result = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);

        return result.PinToken!;
    }

    public async ValueTask<NegotiateSharedSecretResult> NegotiateSharedSecretAsync()
    {
        var command = new AuthenticatorClientPinCommand(pinProtocol: 0x01, subCommand: AuthenticatorClientPinSubCommand.GetKeyAgreement);

        var result = await ExecuteClientPinCommandAsync(command);

        var authenticatorKey = result.KeyAgreement!;

        byte[] sharedSecret = CryptoHelper.GenerateSharedSecret(authenticatorKey, out var platformKey);

        return new NegotiateSharedSecretResult(authenticatorKey, platformKey, sharedSecret);
    }

    protected abstract ValueTask<FidoAuthenticatorResponse> ExecuteCommandAsync(CtapCommand command);
}
