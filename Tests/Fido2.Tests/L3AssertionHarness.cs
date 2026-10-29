using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Objects;

using Microsoft.Extensions.Logging;

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
        byte[] userHandle = null,
        string id = null,
        byte[] rawId = null,
        Fido2Configuration config = null,
        Guid? storedAaGuid = null,
        IMetadataService metadataService = null,
        ILogger<Fido2> logger = null,
        IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredentialId = null,
        bool viaPreAaguidOverload = false,
        AuthenticatorFlags flags = AuthenticatorFlags.UP | AuthenticatorFlags.UV,
        AuthenticatorAttachment? authenticatorAttachment = null)
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
            flags,
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
            Id = id ?? "8dA",
            RawId = rawId ?? CredentialId,
            AuthenticatorAttachment = authenticatorAttachment,
            ClientExtensionResults = clientExtensionResults ?? new AuthenticationExtensionsClientOutputs(),
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = authenticatorData,
                Signature = signature,
                ClientDataJson = clientDataJson,
                UserHandle = omitUserHandle ? null : userHandle ?? [0xf1, 0xd0]
            }
        };

        config ??= new Fido2Configuration
        {
            RPID = Rp,
            RPName = Rp,
            Origins = new HashSet<string> { Rp }
        };

        if (viaPreAaguidOverload)
        {
            // Positionally, with a CancellationToken where storedAaGuid now sits in the newer overload -- how code
            // compiled before that parameter existed calls it.
            return AuthenticatorAssertionResponse.Parse(response).VerifyAsync(
                options, config, credentialPublicKey.GetBytes(), 0,
                isUserHandleOwnerOfCredentialId ?? (static (args, cancellationToken) => Task.FromResult(true)),
                metadataService, null, null, CancellationToken.None);
        }

        var lib = new Fido2(config, metadataService, logger);

        return lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = credentialPublicKey.GetBytes(),
            StoredSignatureCounter = 0,
            StoredAaGuid = storedAaGuid,
            IsUserHandleOwnerOfCredentialIdCallback = isUserHandleOwnerOfCredentialId ?? (static (args, cancellationToken) => Task.FromResult(true))
        });
    }
}
