using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// The FIDO2 Server conformance tests send a well-formed ceremony response with one field deliberately
/// corrupted, and expect the server to reject it -- e.g. F-3 ("id" is not base64url) and F-4 (missing "type").
/// </summary>
public class L3RawResponseValidationTests
{
    private const string Rp = "https://www.passwordless.dev";

    [Fact]
    public async Task AttestationResponseWithNonBase64UrlIdIsRejected()
    {
        byte[] challenge = RandomNumberGenerator.GetBytes(128);
        var acd = AttestedCredentialData.Parse(Convert.FromHexString("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0"));
        byte[] authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(Rp)),
            AuthenticatorFlags.UP | AuthenticatorFlags.AT,
            0,
            acd).ToByteArray();

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.create",
            Challenge = challenge,
            Origin = Rp
        });

        var rawResponse = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "not base64url!!", // valid RawId below, but Id itself does not decode to it
            RawId = [0xf1, 0xd0],
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new CborMap
                {
                    { "fmt", "none" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                ClientDataJson = clientDataJson
            },
        };

        var originalOptions = new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams = [PubKeyCredParam.ES256],
            Rp = new PublicKeyCredentialRpEntity(Rp, Rp, ""),
            User = new Fido2User { Name = "testuser", Id = "testuser"u8.ToArray(), DisplayName = "Test User" },
            Timeout = 60000,
        };

        var lib = new Fido2(new Fido2Configuration
        {
            RPID = Rp,
            RPName = Rp,
            Origins = new HashSet<string> { Rp },
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawResponse,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = static (args, cancellationToken) => Task.FromResult(true)
        }));

        Assert.Equal(Fido2ErrorCode.InvalidAttestationResponse, ex.Code);
    }

    [Fact]
    public async Task AssertionResponseMissingTypeIsRejected()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(false);
        var credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(
            COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, parameters.Q.X, parameters.Q.Y);

        byte[] challenge = RandomNumberGenerator.GetBytes(128);
        byte[] credentialId = [0xf1, 0xd0];

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.get",
            Challenge = challenge,
            Origin = Rp
        });

        byte[] authenticatorData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(Rp)),
            AuthenticatorFlags.UP | AuthenticatorFlags.UV,
            1,
            null).ToByteArray();

        byte[] signature = Fido2Tests.SignData(
            COSE.KeyType.EC2,
            COSE.Algorithm.ES256,
            [.. authenticatorData, .. SHA256.HashData(clientDataJson)],
            ecdsa);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = Rp,
            AllowCredentials = [new PublicKeyCredentialDescriptor(credentialId)],
        };

        var response = new AuthenticatorAssertionRawResponse
        {
            // Type intentionally omitted (defaults to null now, rather than the enum's zero member).
            Id = "8dA",
            RawId = credentialId,
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = authenticatorData,
                Signature = signature,
                ClientDataJson = clientDataJson,
                UserHandle = [0xf1, 0xd0]
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            RPID = Rp,
            RPName = Rp,
            Origins = new HashSet<string> { Rp }
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = credentialPublicKey.GetBytes(),
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = static (args, cancellationToken) => Task.FromResult(true)
        }));

        Assert.Equal(Fido2ErrorCode.InvalidAssertionResponse, ex.Code);
    }
}
