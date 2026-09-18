using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Malformed, attacker-controlled input on the parsing paths must surface as
/// <see cref="Fido2VerificationException"/> rather than a raw runtime exception
/// (ArgumentOutOfRangeException, KeyNotFoundException, InvalidCastException, NullReferenceException),
/// which callers that only guard against Fido2VerificationException would not handle.
/// </summary>
public class MalformedInputHardeningTests
{
    private static byte[] BuildAuthDataWithAttestedCredential(ushort declaredCredentialIdLength, byte[] trailingAcdBytes)
    {
        // rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credentialIdLength(2) + trailing
        var authData = new byte[37 + 16 + 2 + trailingAcdBytes.Length];

        authData[32] = (byte)AuthenticatorFlags.AT;

        // credentialId length, 16-bit big-endian, at offset 37 + 16 = 53
        authData[53] = (byte)(declaredCredentialIdLength >> 8);
        authData[54] = (byte)(declaredCredentialIdLength & 0xFF);

        trailingAcdBytes.CopyTo(authData, 55);

        return authData;
    }

    [Fact]
    public void AuthenticatorData_CredentialIdLength_PastEndOfBuffer_ThrowsFido2()
    {
        // Declared credential ID length (1023) far exceeds the two bytes actually present. Without the
        // bound check this slices past the buffer and throws ArgumentOutOfRangeException.
        byte[] authData = BuildAuthDataWithAttestedCredential(1023, [0x00, 0x00]);

        var ex = Assert.Throws<Fido2VerificationException>(() => AuthenticatorData.Parse(authData));
        Assert.Equal(Fido2ErrorCode.InvalidAttestedCredentialData, ex.Code);
    }

    [Fact]
    public void AssertionResponse_Parse_NullResponse_ThrowsFido2()
    {
        var ex = Assert.Throws<Fido2VerificationException>(
            () => AuthenticatorAssertionResponse.Parse(new AuthenticatorAssertionRawResponse()));
        Assert.Equal(Fido2ErrorCode.InvalidAssertionResponse, ex.Code);
    }

    [Fact]
    public void AssertionResponse_Parse_NullRawResponse_ThrowsFido2()
    {
        Assert.Throws<Fido2VerificationException>(() => AuthenticatorAssertionResponse.Parse(null!));
    }

    [Fact]
    public void AssertionResponse_Parse_CredentialPublicKeyMissingKty_ThrowsFido2()
    {
        // Valid attested-credential-data framing (credentialId length 2, two id bytes) followed by a COSE
        // key map that has an alg (3:-7) but no kty (1). CredentialPublicKey's constructor would throw a raw
        // KeyNotFoundException; the Parse wrapper must convert it.
        byte[] coseKeyMissingKty = [0xA1, 0x03, 0x26]; // { 3: -7 }
        byte[] trailing = [0xAA, 0xBB, .. coseKeyMissingKty]; // 2-byte credentialId + COSE key
        byte[] authData = BuildAuthDataWithAttestedCredential(2, trailing);

        var rawResponse = new AuthenticatorAssertionRawResponse
        {
            Id = "aa",
            RawId = [0xAA, 0xBB],
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = authData,
                Signature = [0x01],
                ClientDataJson = "{}"u8.ToArray(),
            },
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
        };

        Assert.Throws<Fido2VerificationException>(() => AuthenticatorAssertionResponse.Parse(rawResponse));
    }
}
