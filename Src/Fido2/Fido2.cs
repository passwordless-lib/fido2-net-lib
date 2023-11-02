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
    /// Returns CredentialCreateOptions including a challenge to be sent to the browser/authr to create new credentials
    /// </summary>
    /// <returns></returns>
    /// <param name="excludeCredentials">Recommended. This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator.The client is requested to return an error if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.</param>
    public CredentialCreateOptions RequestNewCredential(
        Fido2User user,
        List<PublicKeyCredentialDescriptor> excludeCredentials,
        AuthenticationExtensionsClientInputs? extensions = null)
    {
        return RequestNewCredential(user, excludeCredentials, AuthenticatorSelection.Default, AttestationConveyancePreference.None, extensions);
    }

    /// <summary>
    /// Returns CredentialCreateOptions including a challenge to be sent to the browser/authr to create new credentials
    /// </summary>
    /// <returns></returns>
    /// <param name="attestationPreference">This member is intended for use by Relying Parties that wish to express their preference for attestation conveyance. The default is none.</param>
    /// <param name="excludeCredentials">Recommended. This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator.The client is requested to return an error if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.</param>
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
    /// Verifies the response from the browser/authr after creating new credentials
    /// </summary>
    /// <param name="attestationResponse"></param>
    /// <param name="origChallenge"></param>
    /// <param name="isCredentialIdUniqueToUser"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public async Task<CredentialMakeResult> MakeNewCredentialAsync(
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions origChallenge,
        IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser,
        CancellationToken cancellationToken = default)
    {
        var parsedResponse = AuthenticatorAttestationResponse.Parse(attestationResponse);
        var success = await parsedResponse.VerifyAsync(origChallenge, _config, isCredentialIdUniqueToUser, _metadataService, cancellationToken);

        // todo: Set Errormessage etc.
        return new CredentialMakeResult(
            status: "ok",
            errorMessage: string.Empty,
            result: success
        );
    }

    /// <summary>
    /// Returns AssertionOptions including a challenge to the browser/authr to assert existing credentials and authenticate a user.
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
    /// Verifies the assertion response from the browser/authr to assert existing credentials and authenticate a user.
    /// </summary>
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

    /// <summary>
    /// Result of parsing and verifying attestation. Used to transport Public Key back to RP
    /// </summary>
    public sealed class CredentialMakeResult : Fido2ResponseBase
    {
        public CredentialMakeResult(string status, string errorMessage, RegisteredPublicKeyCredential? result)
        {
            Status = status;
            ErrorMessage = errorMessage;
            Result = result;
        }

        public RegisteredPublicKeyCredential? Result { get; }

        // todo: add debuginfo?
    }
}

/// <summary>
/// Callback function used to validate that the CredentialID is unique to this User
/// </summary>
/// <param name="credentialIdUserParams"></param>
/// <returns></returns>
public delegate Task<bool> IsCredentialIdUniqueToUserAsyncDelegate(IsCredentialIdUniqueToUserParams credentialIdUserParams, CancellationToken cancellationToken);

/// <summary>
/// Callback function used to validate that the user handle is indeed owned of the CredentialId
/// </summary>
/// <param name="credentialIdUserHandleParams"></param>
/// <returns></returns>
public delegate Task<bool> IsUserHandleOwnerOfCredentialIdAsync(IsUserHandleOwnerOfCredentialIdParams credentialIdUserHandleParams, CancellationToken cancellationToken);
