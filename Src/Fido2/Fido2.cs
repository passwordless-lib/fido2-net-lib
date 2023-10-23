using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Public API for parsing and verifying FIDO2 attestation & assertion responses.
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
    /// <returns></returns>
    /// <param name="excludeCredentials">Recommended. This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator. The client is requested to return an error if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.</param>
    public CredentialCreateOptions RequestNewCredential(
        Fido2User user,
        List<PublicKeyCredentialDescriptor> excludeCredentials,
        AuthenticationExtensionsClientInputs? extensions = null)
    {
        return RequestNewCredential(user, excludeCredentials, AuthenticatorSelection.Default, AttestationConveyancePreference.None, extensions);
    }

    /// <summary>
    /// Returns CredentialCreateOptions including a challenge to be sent to the browser/authenticator to create new credentials.
    /// </summary>
    /// <returns></returns>
    /// <param name="attestationPreference">This member is intended for use by Relying Parties that wish to express their preference for attestation conveyance. The default is none.</param>
    /// <param name="excludeCredentials">Recommended. This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator. The client is requested to return an error if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.</param>
    public CredentialCreateOptions RequestNewCredential(
        Fido2User user,
        List<PublicKeyCredentialDescriptor> excludeCredentials,
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
    /// <param name="attestationResponse">The attestation response from the authenticator.</param>
    /// <param name="originalOptions">The original options that was sent to the client.</param>
    /// <param name="isCredentialIdUniqueToUser">The delegate used to validate that the CredentialID is unique to this user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns></returns>
    public async Task<MakeNewCredentialResult> MakeNewCredentialAsync(
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions originalOptions,
        IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser,
        CancellationToken cancellationToken = default)
    {
        var parsedResponse = AuthenticatorAttestationResponse.Parse(attestationResponse);
        var success = await parsedResponse.VerifyAsync(originalOptions, _config, isCredentialIdUniqueToUser, _metadataService, cancellationToken);

        // todo: Set Errormessage etc.
        return new MakeNewCredentialResult(
            status: "ok",
            errorMessage: string.Empty,
            result: success
        );
    }

    /// <summary>
    /// Returns AssertionOptions including a challenge to the browser/authenticator to assert existing credentials and authenticate a user.
    /// </summary>
    /// <returns></returns>
    public AssertionOptions GetAssertionOptions(
        IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials,
        UserVerificationRequirement? userVerification,
        AuthenticationExtensionsClientInputs? extensions = null)
    {
        byte[] challenge = RandomNumberGenerator.GetBytes(_config.ChallengeSize);

        return AssertionOptions.Create(_config, challenge, allowedCredentials, userVerification, extensions);
    }

    /// <summary>
    /// Verifies the assertion response from the browser/authenticator to assert existing credentials and authenticate a user.
    /// </summary>
    /// <param name="assertionResponse">The assertion response from the authenticator.</param>
    /// <param name="originalOptions">The original options that was sent to the client.</param>
    /// <param name="storedPublicKey">The stored credential public key.</param>
    /// <param name="storedDevicePublicKeys">The stored device public keys.</param>
    /// <param name="storedSignatureCounter">The stored value of the signature counter.</param>
    /// <param name="isUserHandleOwnerOfCredentialIdCallback">The delegate used to validate that the user handle is indeed owned of the CredentialId.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns></returns>
    public async Task<VerifyAssertionResult> MakeAssertionAsync(
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions originalOptions,
        byte[] storedPublicKey,
        List<byte[]> storedDevicePublicKeys,
        uint storedSignatureCounter,
        IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredentialIdCallback,
        CancellationToken cancellationToken = default)
    {
        var parsedResponse = AuthenticatorAssertionResponse.Parse(assertionResponse);

        var result = await parsedResponse.VerifyAsync(originalOptions,
                                                      _config,
                                                      storedPublicKey,
                                                      storedDevicePublicKeys,
                                                      storedSignatureCounter,
                                                      isUserHandleOwnerOfCredentialIdCallback,
                                                      _metadataService,
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
