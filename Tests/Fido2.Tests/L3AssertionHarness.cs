using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Runs a complete, correctly signed ES256 assertion, so that a test exercising one rule fails only for
/// that rule rather than for anything else in the ceremony.
/// </summary>
internal static class L3AssertionHarness
{
    internal const string Rp = "https://www.passwordless.dev";

    internal static readonly byte[] CredentialId = [0xf1, 0xd0];

    internal static Task<VerifyAssertionResult> AssertAsync(
        AuthenticationExtensionsClientInputs requestedExtensions,
        AuthenticationExtensionsClientOutputs clientExtensionResults = null,
        IReadOnlyList<PublicKeyCredentialDescriptor> allowCredentials = null,
        bool omitUserHandle = false,
        byte[] userHandle = null)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(false);
        var credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(
            COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, parameters.Q.X, parameters.Q.Y);

        byte[] challenge = RandomNumberGenerator.GetBytes(128);

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
            AllowCredentials = allowCredentials ?? [new PublicKeyCredentialDescriptor(CredentialId)],
            Extensions = requestedExtensions
        };

        var response = new AuthenticatorAssertionRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = CredentialId,
            ClientExtensionResults = clientExtensionResults ?? new AuthenticationExtensionsClientOutputs(),
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = authenticatorData,
                Signature = signature,
                ClientDataJson = clientDataJson,
                UserHandle = omitUserHandle ? null : userHandle ?? [0xf1, 0xd0]
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            RPID = Rp,
            RPName = Rp,
            Origins = new HashSet<string> { Rp }
        });

        return lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = credentialPublicKey.GetBytes(),
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = static (args, cancellationToken) => Task.FromResult(true)
        });
    }
}
