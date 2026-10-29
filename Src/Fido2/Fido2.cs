using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// Public API for parsing and verifying FIDO2 attestation and assertion responses.
/// </summary>
public class Fido2 : IFido2
{
    private readonly Fido2Configuration _config;
    private readonly IMetadataService? _metadataService;
    private readonly ILogger<Fido2>? _logger;

    /// <summary>
    /// Initializes the library for one relying party.
    /// </summary>
    /// <param name="config">The relying party's settings.</param>
    /// <param name="metadataService">Where to look authenticators up during registration, or <see langword="null"/> to skip metadata checks.</param>
    public Fido2(
        Fido2Configuration config,
        IMetadataService? metadataService = null)
        : this(config, metadataService, logger: null)
    {
    }

    /// <summary>
    /// Initializes the library for one relying party, logging the outcome of every ceremony.
    /// </summary>
    /// <param name="config">The relying party's settings.</param>
    /// <param name="metadataService">Where to look authenticators up during registration, or <see langword="null"/> to skip metadata checks.</param>
    /// <param name="logger">
    /// Where to log ceremony outcomes (event IDs 1200-1299), or <see langword="null"/> for no logging. Successful
    /// ceremonies are logged at <see cref="LogLevel.Information"/>, rejected ones at <see cref="LogLevel.Warning"/>
    /// with their <see cref="Fido2ErrorCode"/>, and unexpected failures at <see cref="LogLevel.Error"/>.
    /// </param>
    public Fido2(
        Fido2Configuration config,
        IMetadataService? metadataService,
        ILogger<Fido2>? logger)
    {
        _config = config;
        _metadataService = metadataService;
        _logger = logger;
    }

    /// <summary>
    /// Returns CredentialCreateOptions including a challenge to be sent to the browser/authenticator to create new credentials.
    /// </summary>
    /// <param name="requestNewCredentialParams">The input arguments for generating CredentialCreateOptions</param>
    /// <returns></returns>
    public CredentialCreateOptions RequestNewCredential(RequestNewCredentialParams requestNewCredentialParams)
    {
        var challenge = NewChallenge();
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
        try
        {
            var parsedResponse = AuthenticatorAttestationResponse.Parse(makeNewCredentialParams.AttestationResponse);
            var credential = await parsedResponse.VerifyAsync(makeNewCredentialParams.OriginalOptions, _config, makeNewCredentialParams.IsCredentialIdUniqueToUserCallback, _metadataService, makeNewCredentialParams.RequestTokenBindingId, makeNewCredentialParams.Mediation, cancellationToken, _logger);

            _logger?.RegistrationSucceeded(_config.RPID, credential);
            return credential;
        }
        catch (Fido2VerificationException ex)
        {
            _logger?.RegistrationRejected(_config.RPID, RawIdOf(makeNewCredentialParams), ex);
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException && _logger is not null)
        {
            _logger.CeremonyFailed("registration", RawIdOf(makeNewCredentialParams), ex);
            throw;
        }
    }

    /// <summary>
    /// Returns AssertionOptions including a challenge to the browser/authenticator to assert existing credentials and authenticate a user.
    /// </summary>
    /// <param name="getAssertionOptionsParams">The input arguments for generating AssertionOptions</param>
    /// <returns></returns>
    public AssertionOptions GetAssertionOptions(GetAssertionOptionsParams getAssertionOptionsParams)
    {
        byte[] challenge = NewChallenge();

        return AssertionOptions.Create(_config, challenge, getAssertionOptionsParams.AllowedCredentials, getAssertionOptionsParams.UserVerification, getAssertionOptionsParams.Extensions, getAssertionOptionsParams.Hints);
    }

    public AssertionOptions GetAssertionOptions(
        IReadOnlyList<PublicKeyCredentialDescriptor> allowedCredentials,
        UserVerificationRequirement? userVerification,
        AuthenticationExtensionsClientInputs? extensions = null)
    {
        byte[] challenge = NewChallenge();

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
        var credentialId = RawIdOf(makeAssertionParams);

        try
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
                                                          makeAssertionParams.SecurePaymentConfirmation,
                                                          makeAssertionParams.StoredAaGuid,
                                                          cancellationToken,
                                                          _logger);

            // Both the status re-check and the assertion-time metadata consistency checks need the credential's
            // AAGUID; without it, either setting silently does nothing, which is worth telling whoever enabled it.
            if (makeAssertionParams.StoredAaGuid is null && _metadataService is not null &&
                (_config.RecheckMetadataStatusOnAssertion || _config.MetadataConsistencyStrictness is not MetadataConsistencyStrictness.Off))
                _logger?.MetadataRecheckSkipped(credentialId);

            _logger?.AssertionSucceeded(_config.RPID, result);
            return result;
        }
        catch (Fido2VerificationException ex)
        {
            _logger?.AssertionRejected(_config.RPID, credentialId, ex);
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException && _logger is not null)
        {
            _logger.CeremonyFailed("authentication", credentialId, ex);
            throw;
        }
    }

    // Read without asserting the response is there: a missing one is reported by Parse, and the log should say so
    // rather than fail with a NullReferenceException of its own.
    private static byte[]? RawIdOf(MakeNewCredentialParams parameters) => parameters.AttestationResponse is { } response ? response.RawId : null;

    private static byte[]? RawIdOf(MakeAssertionParams parameters) => parameters.AssertionResponse is { } response ? response.RawId : null;

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

    /// <summary>
    /// The fewest bytes a challenge may have. Challenges "MUST contain enough entropy to make guessing them
    /// infeasible" and "SHOULD therefore be at least 16 bytes long" (WebAuthn §13.4.3): the challenge is the only
    /// thing that ties a response to one ceremony. This library enforces the SHOULD.
    /// </summary>
    public const int MinimumChallengeSize = 16;

    private byte[] NewChallenge()
    {
        if (_config.ChallengeSize < MinimumChallengeSize)
        {
            throw new Fido2ConfigurationException(
                $"{nameof(Fido2Configuration)}.{nameof(Fido2Configuration.ChallengeSize)} is {_config.ChallengeSize}; challenges must be at least {MinimumChallengeSize} bytes.");
        }

        return RandomNumberGenerator.GetBytes(_config.ChallengeSize);
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
