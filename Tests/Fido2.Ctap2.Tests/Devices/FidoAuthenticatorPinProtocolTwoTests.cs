using System.Security.Cryptography;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class FidoAuthenticatorPinProtocolTwoTests
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

    [Fact]
    public async Task NegotiateSharedSecretAsync_WithProtocolTwo_Requests64ByteSharedSecret()
    {
        using var authenticatorEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authenticatorKey = new CredentialPublicKey(authenticatorEcdsa, COSE.Algorithm.ES256);

        var authenticator = new RecordingAuthenticator();

        var responsePayload = new Fido2NetLib.Cbor.CborMap { { 0x01, authenticatorKey.GetCborObject() } }.Encode();
        var message = new byte[1 + responsePayload.Length];
        message[0] = (byte)CtapStatusCode.OK;
        responsePayload.CopyTo(message.AsSpan(1));
        authenticator.NextResponse = new FidoAuthenticatorResponse(message);

        var result = await authenticator.NegotiateSharedSecretAsync(PinUvAuthProtocolTwo.Instance);

        var command = Assert.IsType<AuthenticatorClientPinCommand>(authenticator.LastCommand);
        Assert.Equal(2u, command.PinProtocol);

        Assert.Equal(64, result.SharedSecret.Length);
    }

    [Fact]
    public async Task SetNewPinAsync_WithProtocolTwo_SendsPinProtocolTwoAnd32ByteAuthParam()
    {
        var authenticator = new RecordingAuthenticator
        {
            // authenticatorClientPIN commands ack with an empty CBOR map.
            NextResponse = new FidoAuthenticatorResponse([(byte)CtapStatusCode.OK, 0xA0])
        };

        using var platformEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var platformKey = new CredentialPublicKey(platformEcdsa, COSE.Algorithm.ES256);
        var sharedSecret = RandomNumberGenerator.GetBytes(64);

        await authenticator.SetNewPinAsync("1234", platformKey, sharedSecret, PinUvAuthProtocolTwo.Instance);

        var command = Assert.IsType<AuthenticatorClientPinCommand>(authenticator.LastCommand);

        Assert.Equal(2u, command.PinProtocol);
        Assert.Equal(32, command.PinAuth!.Length);
        // protocol two's encrypt prepends a random 16-byte IV to the ciphertext.
        Assert.Equal(16 + 64, command.NewPinEnc!.Length);
    }
}
