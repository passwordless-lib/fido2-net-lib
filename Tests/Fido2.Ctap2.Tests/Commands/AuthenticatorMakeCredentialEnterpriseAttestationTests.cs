using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorMakeCredentialEnterpriseAttestationTests
{
    private static AuthenticatorMakeCredentialCommand BuildCommand(uint? enterpriseAttestation = null, string[]? attestationFormatsPreference = null)
    {
        return new AuthenticatorMakeCredentialCommand(
            clientDataHash: new byte[32],
            rpEntity: new PublicKeyCredentialRpEntity("example.com", "Acme", null),
            user: new PublicKeyCredentialUserEntity { Id = [1, 2, 3], Name = "user" },
            pubKeyCredParams: [new PubKeyCredParam(COSE.Algorithm.ES256)],
            options: new AuthenticatorMakeCredentialOptions(),
            enterpriseAttestation: enterpriseAttestation,
            attestationFormatsPreference: attestationFormatsPreference);
    }

    private static CborMap DecodePayload(byte[] payload)
    {
        Assert.Equal((byte)CtapCommandType.AuthenticatorMakeCredential, payload[0]);

        return (CborMap)CborObject.Decode(payload.AsMemory(1));
    }

    [Fact]
    public void GetPayload_WithoutEnterpriseAttestation_OmitsMember()
    {
        var command = BuildCommand();

        var map = DecodePayload(command.GetPayload());

        Assert.DoesNotContain(map, kvp => (int)kvp.Key == 0x0A);
        Assert.DoesNotContain(map, kvp => (int)kvp.Key == 0x0B);
    }

    [Fact]
    public void GetPayload_WithEnterpriseAttestation_EncodesMember()
    {
        var command = BuildCommand(enterpriseAttestation: 2);

        var map = DecodePayload(command.GetPayload());

        Assert.Equal(2, (int)map.Single(kvp => (int)kvp.Key == 0x0A).Value);
    }

    [Fact]
    public void GetPayload_WithAttestationFormatsPreference_EncodesOrderedArray()
    {
        var command = BuildCommand(attestationFormatsPreference: ["packed", "none"]);

        var map = DecodePayload(command.GetPayload());

        var formats = (CborArray)map.Single(kvp => (int)kvp.Key == 0x0B).Value;

        Assert.Equal(2, formats.Length);
        Assert.Equal("packed", (string)formats[0]);
        Assert.Equal("none", (string)formats[1]);
    }
}
