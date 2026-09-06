using System.Security.Cryptography;

using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class FidoAuthenticatorPinPermissionsTests
{
    private sealed class RecordingAuthenticator : FidoAuthenticator
    {
        public CtapCommand? LastCommand { get; private set; }
        public FidoAuthenticatorResponse NextResponse { get; set; } = new(CtapStatusCode.OK);

        protected override ValueTask<FidoAuthenticatorResponse> ExecuteCommandAsync(CtapCommand command)
        {
            LastCommand = command;

            return ValueTask.FromResult(NextResponse);
        }
    }

    private static FidoAuthenticatorResponse BuildPinTokenResponse(byte[] pinToken)
    {
        var payload = new CborMap { { 0x02, pinToken } }.Encode();
        var message = new byte[1 + payload.Length];
        message[0] = (byte)CtapStatusCode.OK;
        payload.CopyTo(message.AsSpan(1));

        return new FidoAuthenticatorResponse(message);
    }

    [Fact]
    public async Task GetPinUvAuthTokenUsingPinWithPermissionsAsync_SendsPermissionsAndRpId()
    {
        var authenticator = new RecordingAuthenticator
        {
            NextResponse = BuildPinTokenResponse(Convert.FromHexString("00112233445566778899aabbccddeeff"))
        };

        using var platformEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var platformKey = new CredentialPublicKey(platformEcdsa, COSE.Algorithm.ES256);
        var sharedSecret = RandomNumberGenerator.GetBytes(32);

        var pinToken = await authenticator.GetPinUvAuthTokenUsingPinWithPermissionsAsync(
            "1234",
            platformKey,
            sharedSecret,
            PinUvAuthTokenPermissions.MakeCredential | PinUvAuthTokenPermissions.GetAssertion,
            rpId: "example.com");

        var command = Assert.IsType<AuthenticatorClientPinCommand>(authenticator.LastCommand);

        Assert.Equal(AuthenticatorClientPinSubCommand.GetPinUvAuthTokenUsingPinWithPermissions, command.SubCommand);
        Assert.Equal(PinUvAuthTokenPermissions.MakeCredential | PinUvAuthTokenPermissions.GetAssertion, command.Permissions);
        Assert.Equal("example.com", command.RpId);
        Assert.NotNull(command.PinHashEnc);
        Assert.Equal(Convert.FromHexString("00112233445566778899aabbccddeeff"), pinToken);
    }

    [Fact]
    public async Task GetPinUvAuthTokenUsingUvWithPermissionsAsync_SendsNoPinHashEnc()
    {
        var authenticator = new RecordingAuthenticator
        {
            NextResponse = BuildPinTokenResponse(Convert.FromHexString("ffeeddccbbaa99887766554433221100"))
        };

        using var platformEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var platformKey = new CredentialPublicKey(platformEcdsa, COSE.Algorithm.ES256);

        var pinToken = await authenticator.GetPinUvAuthTokenUsingUvWithPermissionsAsync(
            platformKey,
            PinUvAuthTokenPermissions.BioEnrollment);

        var command = Assert.IsType<AuthenticatorClientPinCommand>(authenticator.LastCommand);

        Assert.Equal(AuthenticatorClientPinSubCommand.GetPinUvAuthTokenUsingUvWithPermissions, command.SubCommand);
        Assert.Equal(PinUvAuthTokenPermissions.BioEnrollment, command.Permissions);
        Assert.Null(command.RpId);
        Assert.Null(command.PinHashEnc);
        Assert.Equal(Convert.FromHexString("ffeeddccbbaa99887766554433221100"), pinToken);
    }

    [Fact]
    public async Task GetUVRetriesAsync_ReturnsUVRetriesFromResponse()
    {
        var payload = new CborMap { { 0x05, 3 } }.Encode();
        var message = new byte[1 + payload.Length];
        message[0] = (byte)CtapStatusCode.OK;
        payload.CopyTo(message.AsSpan(1));

        var authenticator = new RecordingAuthenticator
        {
            NextResponse = new FidoAuthenticatorResponse(message)
        };

        var retries = await authenticator.GetUVRetriesAsync();

        var command = Assert.IsType<AuthenticatorClientPinCommand>(authenticator.LastCommand);
        Assert.Equal(AuthenticatorClientPinSubCommand.GetUVRetries, command.SubCommand);
        Assert.Equal(3, retries);
    }
}
