using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Public API for parsing and verifying FIDO2 attestation and assertion responses.
/// </summary>
public class Fido2 : IFido2
{
    private readonly Fido2Configuration _config;
    private readonly IMetadataService? _metadataService;

    public Fido2(
        Fido2Configuration config,
        IMetadataService? metadataService = null)
    {
        _config = config;
        _metadataService = metadataService;
    }

    /// <summary>
    /// Returns CredentialCreateOptions including a challenge to be sent to the browser/authenticator to create new credentials.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="excludeCredentials">Recommended. This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator. The client is requested to return an error if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.</param>
    /// <param name="extensions"></param>
    /// <returns></returns>
    public CredentialCreateOptions RequestNewCredential(
        Fido2User user,
        IReadOnlyList<PublicKeyCredentialDescriptor> excludeCredentials,
        AuthenticationExtensionsClientInputs? extensions = null)
    {
        return RequestNewCredential(user, excludeCredentials, AuthenticatorSelection.Default, AttestationConveyancePreference.None, extensions);
    }

    /// <summary>
    /// Returns CredentialCreateOptions including a challenge to be sent to the browser/authenticator to create new credentials.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="excludeCredentials">Recommended. This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator. The client is requested to return an error if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.</param>
    /// <param name="authenticatorSelection"></param>
    /// <param name="attestationPreference">This member is intended for use by Relying Parties that wish to express their preference for attestation conveyance. The default is none.</param>
    /// <param name="extensions"></param>
    /// <returns></returns>
    public CredentialCreateOptions RequestNewCredential(
        Fido2User user,
        IReadOnlyList<PublicKeyCredentialDescriptor> excludeCredentials,
        AuthenticatorSelection authenticatorSelection,
        AttestationConveyancePreference attestationPreference,
        AuthenticationExtensionsClientInputs? extensions = null)
    {
        byte[] challenge = RandomNumberGenerator.GetBytes(_config.ChallengeSize);

        return CredentialCreateOptions.Create(_config, challenge, user, authenticatorSelection, attestationPreference, excludeCredentials, extensions);
    }

    /// <summary>
    /// Verifies the response from the browser/authenticator after creating new credentials.
    /// </summary>
    /// <param name="makeNewCredentialParams">Wraps the input parameters for making a new credential</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns></returns>
    public async Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(MakeNewCredentialParams makeNewCredentialParams,
        CancellationToken cancellationToken = default)
    {
        var parsedResponse = AuthenticatorAttestationResponse.Parse(makeNewCredentialParams.AttestationResponse);
        var credential = await parsedResponse.VerifyAsync(makeNewCredentialParams.OriginalOptions, _config, makeNewCredentialParams.IsCredentialIdUniqueToUserCallback, _metadataService, makeNewCredentialParams.RequestTokenBindingId, cancellationToken);

        return credential;
    }

    /// <summary>
    /// Returns AssertionOptions including a challenge to the browser/authenticator to assert existing credentials and authenticate a user.
    /// </summary>
    /// <param name="allowedCredentials"></param>
    /// <param name="userVerification"></param>
    /// <param name="extensions"></param>
    /// <returns></returns>
    public AssertionOptions GetAssertionOptions(
        IReadOnlyList<PublicKeyCredentialDescriptor> allowedCredentials,
        UserVerificationRequirement? userVerification,
        AuthenticationExtensionsClientInputs? extensions = null)
    {
        byte[] challenge = RandomNumberGenerator.GetBytes(_config.ChallengeSize);

        return AssertionOptions.Create(_config, challenge, allowedCredentials, userVerification, extensions);
    }

    /// <summary>
    /// Verifies the assertion response from the browser/authenticator to assert existing credentials and authenticate a user.
    /// </summary>
    /// <param name="makeAssertionParams">Wraps the input arguments for asserting a passkey</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns></returns>
    public async Task<VerifyAssertionResult> MakeAssertionAsync(MakeAssertionParams makeAssertionParams,
        CancellationToken cancellationToken = default)
    {
        var parsedResponse = AuthenticatorAssertionResponse.Parse(makeAssertionParams.AssertionResponse);

        var result = await parsedResponse.VerifyAsync(makeAssertionParams.OriginalOptions,
                                                      _config,
                                                      makeAssertionParams.StoredPublicKey,
                                                      makeAssertionParams.StoredDevicePublicKeys,
                                                      makeAssertionParams.StoredSignatureCounter,
                                                      makeAssertionParams.IsUserHandleOwnerOfCredentialIdCallback,
                                                      _metadataService,
                                                      makeAssertionParams.RequestTokenBindingId,
                                                      cancellationToken);

        return result;
    }
}

/// <summary>
/// Callback function used to validate that the CredentialID is unique to this user.
/// </summary>
/// <param name="credentialIdUserParams"></param>
/// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
/// <returns></returns>
public delegate Task<bool> IsCredentialIdUniqueToUserAsyncDelegate(IsCredentialIdUniqueToUserParams credentialIdUserParams, CancellationToken cancellationToken);

/// <summary>
/// Callback function used to validate that the user handle is indeed owned of the CredentialId.
/// </summary>
/// <param name="credentialIdUserHandleParams"></param>
/// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
/// <returns></returns>
public delegate Task<bool> IsUserHandleOwnerOfCredentialIdAsync(IsUserHandleOwnerOfCredentialIdParams credentialIdUserHandleParams, CancellationToken cancellationToken);
