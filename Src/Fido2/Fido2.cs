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
    /// <param name="requestNewCredentialParams">The input arguments for generating CredentialCreateOptions</param>
    /// <returns></returns>
    public CredentialCreateOptions RequestNewCredential(RequestNewCredentialParams requestNewCredentialParams)
    {
        var challenge = RandomNumberGenerator.GetBytes(_config.ChallengeSize);
        return CredentialCreateOptions.Create(_config, challenge, requestNewCredentialParams.User, requestNewCredentialParams.AuthenticatorSelection, requestNewCredentialParams.AttestationPreference, requestNewCredentialParams.ExcludeCredentials, requestNewCredentialParams.Extensions, requestNewCredentialParams.PubKeyCredParams, requestNewCredentialParams.Hints, requestNewCredentialParams.AttestationFormats);

    }

    /// <summary>
    /// Verifies the response from the browser/authenticator after creating new credentials.
    /// </summary>
    /// <param name="makeNewCredentialParams">The input arguments for creating a passkey</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns></returns>
    public async Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(MakeNewCredentialParams makeNewCredentialParams,
        CancellationToken cancellationToken = default)
    {
        var parsedResponse = AuthenticatorAttestationResponse.Parse(makeNewCredentialParams.AttestationResponse);
        var credential = await parsedResponse.VerifyAsync(makeNewCredentialParams.OriginalOptions, _config, makeNewCredentialParams.IsCredentialIdUniqueToUserCallback, _metadataService, makeNewCredentialParams.RequestTokenBindingId, makeNewCredentialParams.Mediation, cancellationToken);

        return credential;
    }

    /// <summary>
    /// Returns AssertionOptions including a challenge to the browser/authenticator to assert existing credentials and authenticate a user.
    /// </summary>
    /// <param name="getAssertionOptionsParams">The input arguments for generating AssertionOptions</param>
    /// <returns></returns>
    public AssertionOptions GetAssertionOptions(GetAssertionOptionsParams getAssertionOptionsParams)
    {
        byte[] challenge = RandomNumberGenerator.GetBytes(_config.ChallengeSize);

        return AssertionOptions.Create(_config, challenge, getAssertionOptionsParams.AllowedCredentials, getAssertionOptionsParams.UserVerification, getAssertionOptionsParams.Extensions, getAssertionOptionsParams.Hints);
    }

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
    /// <param name="makeAssertionParams">The input arguments for asserting a passkey</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns></returns>
    public async Task<VerifyAssertionResult> MakeAssertionAsync(MakeAssertionParams makeAssertionParams,
        CancellationToken cancellationToken = default)
    {
        var parsedResponse = AuthenticatorAssertionResponse.Parse(makeAssertionParams.AssertionResponse);

        var result = await parsedResponse.VerifyAsync(makeAssertionParams.OriginalOptions,
                                                      _config,
                                                      makeAssertionParams.StoredPublicKey,
                                                      makeAssertionParams.StoredSignatureCounter,
                                                      makeAssertionParams.IsUserHandleOwnerOfCredentialIdCallback,
                                                      _metadataService,
                                                      makeAssertionParams.RequestTokenBindingId,
                                                      makeAssertionParams.StoredBackupEligible,
                                                      cancellationToken);

        return result;
    }

    /// <summary>
    /// Builds the payload for <c>PublicKeyCredential.signalUnknownCredential()</c>, to tell an authenticator that
    /// a credential it offered is no longer known to this Relying Party.
    /// </summary>
    /// <param name="credentialId">The credential ID this Relying Party does not recognize.</param>
    public UnknownCredentialOptions GetUnknownCredentialOptions(byte[] credentialId)
    {
        return new UnknownCredentialOptions { RpId = _config.RPID, CredentialId = credentialId };
    }

    /// <summary>
    /// Builds the payload for <c>PublicKeyCredential.signalAllAcceptedCredentials()</c>.
    /// </summary>
    /// <param name="userId">The user handle whose credentials are being enumerated.</param>
    /// <param name="allAcceptedCredentialIds">
    /// Every credential ID still registered to the user. This must be exhaustive -- an authenticator may delete
    /// credentials that are absent from it.
    /// </param>
    public AllAcceptedCredentialsOptions GetAllAcceptedCredentialsOptions(byte[] userId, IReadOnlyList<byte[]> allAcceptedCredentialIds)
    {
        return new AllAcceptedCredentialsOptions
        {
            RpId = _config.RPID,
            UserId = userId,
            AllAcceptedCredentialIds = allAcceptedCredentialIds
        };
    }

    /// <summary>
    /// Builds the payload for <c>PublicKeyCredential.signalCurrentUserDetails()</c>, so an authenticator can
    /// refresh the name and display name it shows for the user's credentials.
    /// </summary>
    public CurrentUserDetailsOptions GetCurrentUserDetailsOptions(Fido2User user)
    {
        return new CurrentUserDetailsOptions
        {
            RpId = _config.RPID,
            UserId = user.Id,
            Name = user.Name,
            DisplayName = user.DisplayName
        };
    }
}

/// <summary>
/// Callback function used to validate that the credential ID is not yet registered for any user.
/// </summary>
/// <remarks>
/// Step 26 of WebAuthn Level 3 §7.1: "verify that the credentialId is not yet registered for any user. If
/// the credentialId is already known then the Relying Party SHOULD fail this registration ceremony." Level 2
/// asked only whether the credential belonged to a <em>different</em> user; Level 3 widened it, because an
/// attacker who obtained a credential ID and public key could otherwise register a victim's credential as
/// their own. Return <see langword="false"/> if the credential ID is known at all, whoever holds it --
/// <see cref="IsCredentialIdUniqueToUserParams.User"/> is supplied for logging and for Relying Parties that
/// deliberately keep the narrower Level 2 behaviour.
/// </remarks>
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
