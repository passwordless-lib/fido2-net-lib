using System.Security.Cryptography;
using System.Text;

using Fido2NetLib.Cbor;
using Fido2NetLib.Ctap2;
using Fido2NetLib.Objects;

public abstract class FidoAuthenticator
{
    public async ValueTask<AuthenticatorMakeCredentialResponse> MakeCredentialAsync(AuthenticatorMakeCredentialCommand command)
    {
        var result = await ExecuteCommandAsync(command);

        result.CheckStatus();

        return AuthenticatorMakeCredentialResponse.FromCborObject(result.GetCborObject());
    }

    public async ValueTask<AuthenticatorGetAssertionResponse> GetAssertionAsync(AuthenticatorGetAssertionCommand command)
    {
        var result = await ExecuteCommandAsync(command);

        result.CheckStatus();

        return AuthenticatorGetAssertionResponse.FromCborObject(result.GetCborObject());
    }

    public async ValueTask<AuthenticatorGetInfoResponse> GetInfoAsync()
    {
        var result = await ExecuteCommandAsync(new AuthenticatorGetInfoCommand());

        result.CheckStatus();

        return AuthenticatorGetInfoResponse.FromCborObject(result.GetCborObject());
    }


    public async ValueTask<AuthenticatorClientPinResponse> ExecuteClientPinCommandAsync(AuthenticatorClientPinCommand command)
    {
        var result = await ExecuteCommandAsync(command);

        result.CheckStatus();

        return AuthenticatorClientPinResponse.FromCborObject(result.GetCborObject());
    }

    public async ValueTask<AuthenticatorResetResponse> ResetAsync()
    {
        var result = await ExecuteCommandAsync(new AuthenticatorResetCommand());

        result.CheckStatus();

        return new AuthenticatorResetResponse();
    }

    public async ValueTask<AuthenticatorGetNextAssertionResponse> GetNextAssertionAsync()
    {
        var result = await ExecuteCommandAsync(new AuthenticatorGetNextAssertionCommand());

        result.CheckStatus();

        return AuthenticatorGetNextAssertionResponse.FromCborObject(result.GetCborObject());
    }

    /// <summary>
    /// Invokes the authenticatorSelection command, asking the user to select this authenticator
    /// (e.g. among several plugged in at once) by requesting user presence.
    /// </summary>
    public async ValueTask SelectAsync()
    {
        var result = await ExecuteCommandAsync(new AuthenticatorSelectionCommand());

        result.CheckStatus();
    }

    public async ValueTask<AuthenticatorConfigResponse> ExecuteConfigCommandAsync(AuthenticatorConfigCommand command)
    {
        var result = await ExecuteCommandAsync(command);

        result.CheckStatus();

        return new AuthenticatorConfigResponse();
    }

    public async ValueTask<AuthenticatorBioEnrollmentResponse> ExecuteBioEnrollmentCommandAsync(AuthenticatorBioEnrollmentCommand command)
    {
        var result = await ExecuteCommandAsync(command);

        result.CheckStatus();

        if (result.Data.IsEmpty)
        {
            return new AuthenticatorBioEnrollmentResponse();
        }

        return AuthenticatorBioEnrollmentResponse.FromCborObject(result.GetCborObject());
    }

    /// <summary>
    /// Invokes authenticatorBioEnrollment with getModality, returning the user verification
    /// modality (e.g. fingerprint) supported by the authenticator.
    /// </summary>
    public async ValueTask<AuthenticatorBioEnrollmentResponse> GetBioModalityAsync()
    {
        var command = new AuthenticatorBioEnrollmentCommand(getModality: true);

        return await ExecuteBioEnrollmentCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorBioEnrollment getFingerprintSensorInfo sub command.
    /// </summary>
    public async ValueTask<AuthenticatorBioEnrollmentResponse> GetFingerprintSensorInfoAsync()
    {
        var command = new AuthenticatorBioEnrollmentCommand(
            AuthenticatorBioEnrollmentModality.Fingerprint,
            AuthenticatorBioEnrollmentSubCommand.GetFingerprintSensorInfo);

        return await ExecuteBioEnrollmentCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorBioEnrollment enrollBegin sub command, starting a new fingerprint
    /// enrollment and requesting the first sample capture.
    /// </summary>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>be</c> permission.</param>
    /// <param name="timeoutMilliseconds">An optional capture timeout, in milliseconds.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask<AuthenticatorBioEnrollmentResponse> EnrollFingerprintBeginAsync(byte[] pinUvAuthToken, int? timeoutMilliseconds = null, uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorBioEnrollmentSubCommand.EnrollBegin;

        CborMap? subCommandParams = null;

        if (timeoutMilliseconds.HasValue)
        {
            subCommandParams = new CborMap { { 0x03, timeoutMilliseconds.Value } };
        }

        var pinUvAuthParam = ComputeBioEnrollmentPinUvAuthParam(pinUvAuthToken, AuthenticatorBioEnrollmentModality.Fingerprint, subCommand, subCommandParams, pinUvAuthProtocol);

        var command = new AuthenticatorBioEnrollmentCommand(
            AuthenticatorBioEnrollmentModality.Fingerprint,
            subCommand,
            subCommandParams,
            pinUvAuthProtocol,
            pinUvAuthParam);

        return await ExecuteBioEnrollmentCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorBioEnrollment enrollCaptureNextSample sub command, requesting the
    /// next sample capture for an enrollment already started with <see cref="EnrollFingerprintBeginAsync"/>.
    /// </summary>
    /// <param name="templateId">The template identifier returned by <see cref="EnrollFingerprintBeginAsync"/>.</param>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>be</c> permission.</param>
    /// <param name="timeoutMilliseconds">An optional capture timeout, in milliseconds.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask<AuthenticatorBioEnrollmentResponse> EnrollFingerprintCaptureNextSampleAsync(
        byte[] templateId,
        byte[] pinUvAuthToken,
        int? timeoutMilliseconds = null,
        uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorBioEnrollmentSubCommand.EnrollCaptureNextSample;

        var subCommandParams = new CborMap { { 0x01, templateId } };

        if (timeoutMilliseconds.HasValue)
        {
            subCommandParams.Add(0x03, timeoutMilliseconds.Value);
        }

        var pinUvAuthParam = ComputeBioEnrollmentPinUvAuthParam(pinUvAuthToken, AuthenticatorBioEnrollmentModality.Fingerprint, subCommand, subCommandParams, pinUvAuthProtocol);

        var command = new AuthenticatorBioEnrollmentCommand(
            AuthenticatorBioEnrollmentModality.Fingerprint,
            subCommand,
            subCommandParams,
            pinUvAuthProtocol,
            pinUvAuthParam);

        return await ExecuteBioEnrollmentCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorBioEnrollment cancelCurrentEnrollment sub command. Unauthenticated per §6.7.5.
    /// </summary>
    public async ValueTask CancelCurrentEnrollmentAsync()
    {
        var command = new AuthenticatorBioEnrollmentCommand(
            AuthenticatorBioEnrollmentModality.Fingerprint,
            AuthenticatorBioEnrollmentSubCommand.CancelCurrentEnrollment);

        _ = await ExecuteBioEnrollmentCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorBioEnrollment enumerateEnrollments sub command.
    /// </summary>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>be</c> permission.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask<AuthenticatorBioEnrollmentResponse> EnumerateFingerprintEnrollmentsAsync(byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorBioEnrollmentSubCommand.EnumerateEnrollments;

        var pinUvAuthParam = ComputeBioEnrollmentPinUvAuthParam(pinUvAuthToken, AuthenticatorBioEnrollmentModality.Fingerprint, subCommand, subCommandParams: null, pinUvAuthProtocol);

        var command = new AuthenticatorBioEnrollmentCommand(
            AuthenticatorBioEnrollmentModality.Fingerprint,
            subCommand,
            pinUvAuthProtocol: pinUvAuthProtocol,
            pinUvAuthParam: pinUvAuthParam);

        return await ExecuteBioEnrollmentCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorBioEnrollment setFriendlyName sub command, renaming an existing
    /// fingerprint enrollment.
    /// </summary>
    /// <param name="templateId">The template identifier to rename.</param>
    /// <param name="templateFriendlyName">The new friendly name.</param>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>be</c> permission.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask SetFingerprintFriendlyNameAsync(byte[] templateId, string templateFriendlyName, byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorBioEnrollmentSubCommand.SetFriendlyName;

        var subCommandParams = new CborMap
        {
            { 0x01, templateId },
            { 0x02, templateFriendlyName }
        };

        var pinUvAuthParam = ComputeBioEnrollmentPinUvAuthParam(pinUvAuthToken, AuthenticatorBioEnrollmentModality.Fingerprint, subCommand, subCommandParams, pinUvAuthProtocol);

        var command = new AuthenticatorBioEnrollmentCommand(
            AuthenticatorBioEnrollmentModality.Fingerprint,
            subCommand,
            subCommandParams,
            pinUvAuthProtocol,
            pinUvAuthParam);

        _ = await ExecuteBioEnrollmentCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorBioEnrollment removeEnrollment sub command, deleting an existing
    /// fingerprint enrollment.
    /// </summary>
    /// <param name="templateId">The template identifier to remove.</param>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>be</c> permission.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask RemoveFingerprintEnrollmentAsync(byte[] templateId, byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorBioEnrollmentSubCommand.RemoveEnrollment;

        var subCommandParams = new CborMap { { 0x01, templateId } };

        var pinUvAuthParam = ComputeBioEnrollmentPinUvAuthParam(pinUvAuthToken, AuthenticatorBioEnrollmentModality.Fingerprint, subCommand, subCommandParams, pinUvAuthProtocol);

        var command = new AuthenticatorBioEnrollmentCommand(
            AuthenticatorBioEnrollmentModality.Fingerprint,
            subCommand,
            subCommandParams,
            pinUvAuthProtocol,
            pinUvAuthParam);

        _ = await ExecuteBioEnrollmentCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes the pinUvAuthParam for an authenticatorBioEnrollment request:
    /// <c>authenticate(pinUvAuthToken, modality || subCommand || subCommandParams)</c>, where
    /// <c>subCommandParams</c> is only included, CBOR-encoded, when present. Note this is keyed
    /// off the modality byte, not the command's own opcode (0x09) or a 32×0xff prefix.
    /// </summary>
    private static byte[] ComputeBioEnrollmentPinUvAuthParam(
        byte[] pinUvAuthToken,
        AuthenticatorBioEnrollmentModality modality,
        AuthenticatorBioEnrollmentSubCommand subCommand,
        CborMap? subCommandParams,
        uint pinUvAuthProtocol)
    {
        byte[] encodedParams = subCommandParams?.Encode() ?? [];

        var message = new byte[2 + encodedParams.Length];
        message[0] = (byte)modality;
        message[1] = (byte)subCommand;
        encodedParams.CopyTo(message.AsSpan(2));

        return PinUvAuthProtocol.Select(pinUvAuthProtocol).Authenticate(pinUvAuthToken, message);
    }

    public async ValueTask<AuthenticatorCredentialManagementResponse> ExecuteCredentialManagementCommandAsync(AuthenticatorCredentialManagementCommand command)
    {
        var result = await ExecuteCommandAsync(command);

        result.CheckStatus();

        return AuthenticatorCredentialManagementResponse.FromCborObject(result.GetCborObject());
    }

    /// <summary>
    /// Invokes the authenticatorCredentialManagement getCredsMetadata sub command, returning the
    /// number of discoverable credentials stored and an estimate of how many more can be created.
    /// </summary>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>cm</c> or <c>pcmr</c> permission and no associated permissions RP ID.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask<AuthenticatorCredentialManagementResponse> GetCredsMetadataAsync(byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorCredentialManagementSubCommand.GetCredsMetadata;

        var pinUvAuthParam = ComputeCredentialManagementPinUvAuthParam(pinUvAuthToken, subCommand, subCommandParams: null, pinUvAuthProtocol);

        var command = new AuthenticatorCredentialManagementCommand(subCommand, pinUvAuthProtocol: pinUvAuthProtocol, pinUvAuthParam: pinUvAuthParam);

        return await ExecuteCredentialManagementCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Enumerates every RP with discoverable credentials on the authenticator, driving the
    /// enumerateRPsBegin/enumerateRPsGetNextRP sub command pair to completion.
    /// </summary>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>cm</c> or <c>pcmr</c> permission and no associated permissions RP ID.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask<IReadOnlyList<AuthenticatorCredentialManagementResponse>> EnumerateRPsAsync(byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var beginSubCommand = AuthenticatorCredentialManagementSubCommand.EnumerateRPsBegin;

        var pinUvAuthParam = ComputeCredentialManagementPinUvAuthParam(pinUvAuthToken, beginSubCommand, subCommandParams: null, pinUvAuthProtocol);

        var beginCommand = new AuthenticatorCredentialManagementCommand(beginSubCommand, pinUvAuthProtocol: pinUvAuthProtocol, pinUvAuthParam: pinUvAuthParam);

        var first = await ExecuteCredentialManagementCommandAsync(beginCommand).ConfigureAwait(false);

        var results = new List<AuthenticatorCredentialManagementResponse> { first };

        var remaining = (first.TotalRPs ?? 1) - 1;

        for (int i = 0; i < remaining; i++)
        {
            var nextCommand = new AuthenticatorCredentialManagementCommand(AuthenticatorCredentialManagementSubCommand.EnumerateRPsGetNextRP);

            results.Add(await ExecuteCredentialManagementCommandAsync(nextCommand).ConfigureAwait(false));
        }

        return results;
    }

    /// <summary>
    /// Enumerates every discoverable credential for a given RP, driving the
    /// enumerateCredentialsBegin/enumerateCredentialsGetNextCredential sub command pair to completion.
    /// </summary>
    /// <param name="rpIdHash">The SHA-256 hash of the RP ID to enumerate credentials for.</param>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>cm</c> or <c>pcmr</c> permission.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask<IReadOnlyList<AuthenticatorCredentialManagementResponse>> EnumerateCredentialsAsync(byte[] rpIdHash, byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var beginSubCommand = AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsBegin;

        var subCommandParams = new CborMap { { 0x01, rpIdHash } };

        var pinUvAuthParam = ComputeCredentialManagementPinUvAuthParam(pinUvAuthToken, beginSubCommand, subCommandParams, pinUvAuthProtocol);

        var beginCommand = new AuthenticatorCredentialManagementCommand(beginSubCommand, subCommandParams, pinUvAuthProtocol, pinUvAuthParam);

        var first = await ExecuteCredentialManagementCommandAsync(beginCommand).ConfigureAwait(false);

        var results = new List<AuthenticatorCredentialManagementResponse> { first };

        var remaining = (first.TotalCredentials ?? 1) - 1;

        for (int i = 0; i < remaining; i++)
        {
            var nextCommand = new AuthenticatorCredentialManagementCommand(AuthenticatorCredentialManagementSubCommand.EnumerateCredentialsGetNextCredential);

            results.Add(await ExecuteCredentialManagementCommandAsync(nextCommand).ConfigureAwait(false));
        }

        return results;
    }

    /// <summary>
    /// Invokes the authenticatorCredentialManagement deleteCredential sub command.
    /// </summary>
    /// <param name="credentialId">The credential to delete.</param>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>cm</c> permission.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask DeleteCredentialAsync(PublicKeyCredentialDescriptor credentialId, byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorCredentialManagementSubCommand.DeleteCredential;

        var subCommandParams = new CborMap { { 0x02, credentialId.ToCborObject() } };

        var pinUvAuthParam = ComputeCredentialManagementPinUvAuthParam(pinUvAuthToken, subCommand, subCommandParams, pinUvAuthProtocol);

        var command = new AuthenticatorCredentialManagementCommand(subCommand, subCommandParams, pinUvAuthProtocol, pinUvAuthParam);

        _ = await ExecuteCredentialManagementCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorCredentialManagement updateUserInformation sub command.
    /// </summary>
    /// <param name="credentialId">The credential whose user information should be updated.</param>
    /// <param name="user">
    /// The updated user information. <see cref="PublicKeyCredentialUserEntity.Id"/> MUST match the
    /// target credential's existing user ID; only <c>name</c> and <c>displayName</c> are replaced.
    /// </param>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>cm</c> permission.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask UpdateUserInformationAsync(PublicKeyCredentialDescriptor credentialId, PublicKeyCredentialUserEntity user, byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorCredentialManagementSubCommand.UpdateUserInformation;

        var subCommandParams = new CborMap
        {
            { 0x02, credentialId.ToCborObject() },
            { 0x03, user.ToCborObject() }
        };

        var pinUvAuthParam = ComputeCredentialManagementPinUvAuthParam(pinUvAuthToken, subCommand, subCommandParams, pinUvAuthProtocol);

        var command = new AuthenticatorCredentialManagementCommand(subCommand, subCommandParams, pinUvAuthProtocol, pinUvAuthParam);

        _ = await ExecuteCredentialManagementCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes the pinUvAuthParam for an authenticatorCredentialManagement request. Unlike
    /// authenticatorConfig, this is NOT prefixed with 32×0xff or the command's own opcode:
    /// <c>authenticate(pinUvAuthToken, subCommand || subCommandParams)</c>, where
    /// <c>subCommandParams</c> is only included, CBOR-encoded, when present.
    /// </summary>
    private static byte[] ComputeCredentialManagementPinUvAuthParam(byte[] pinUvAuthToken, AuthenticatorCredentialManagementSubCommand subCommand, CborMap? subCommandParams, uint pinUvAuthProtocol)
    {
        byte[] encodedParams = subCommandParams?.Encode() ?? [];

        var message = new byte[1 + encodedParams.Length];
        message[0] = (byte)subCommand;
        encodedParams.CopyTo(message.AsSpan(1));

        return PinUvAuthProtocol.Select(pinUvAuthProtocol).Authenticate(pinUvAuthToken, message);
    }

    private const int DefaultMaxFragmentLength = 960; // maxMsgSize default (1024) - 64

    public async ValueTask<AuthenticatorLargeBlobsResponse> ExecuteLargeBlobsCommandAsync(AuthenticatorLargeBlobsCommand command)
    {
        var result = await ExecuteCommandAsync(command);

        result.CheckStatus();

        // Successful "set" (write) requests return an empty response with no CBOR payload.
        if (command.Set != null || result.Data.IsEmpty)
        {
            return new AuthenticatorLargeBlobsResponse();
        }

        return AuthenticatorLargeBlobsResponse.FromCborObject(result.GetCborObject());
    }

    /// <summary>
    /// Reads the authenticator's full serialized large-blob array by repeatedly invoking
    /// authenticatorLargeBlobs with <c>get</c>, per §6.10.2. Does not validate the trailing hash;
    /// use <see cref="LargeBlobArray.TryDecode"/> on the result to do so.
    /// </summary>
    /// <param name="maxFragmentLength">
    /// The per-authenticator <c>maxFragmentLength</c> (<c>maxMsgSize - 64</c> from authenticatorGetInfo,
    /// defaulting to 960). Pass the authenticator's actual value when known.
    /// </param>
    public async ValueTask<byte[]> ReadLargeBlobArrayAsync(int maxFragmentLength = DefaultMaxFragmentLength)
    {
        using var buffer = new MemoryStream();

        uint offset = 0;

        while (true)
        {
            var command = new AuthenticatorLargeBlobsCommand(offset, get: maxFragmentLength);

            var response = await ExecuteLargeBlobsCommandAsync(command).ConfigureAwait(false);

            var fragment = response.Config ?? [];

            buffer.Write(fragment);

            offset += (uint)fragment.Length;

            if (fragment.Length < maxFragmentLength)
            {
                break;
            }
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// Writes a full serialized large-blob array to the authenticator, per §6.10.2, splitting it
    /// into <paramref name="maxFragmentLength"/>-sized <c>set</c> fragments as needed.
    /// </summary>
    /// <param name="serializedLargeBlobArray">
    /// The complete serialized large-blob array to write, including its trailing 16-byte hash
    /// (as produced by <see cref="LargeBlobArray.Encode"/>).
    /// </param>
    /// <param name="pinUvAuthToken">
    /// A pinUvAuthToken with the <c>lbw</c> permission. Required (non-null) if the authenticator
    /// requires user verification or has the <c>alwaysUv</c> option enabled; the authenticator
    /// will reject non-initial fragments with a missing pinUvAuthParam in that case.
    /// </param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    /// <param name="maxFragmentLength">
    /// The per-authenticator <c>maxFragmentLength</c> (<c>maxMsgSize - 64</c> from authenticatorGetInfo,
    /// defaulting to 960). Pass the authenticator's actual value when known.
    /// </param>
    public async ValueTask WriteLargeBlobArrayAsync(
        byte[] serializedLargeBlobArray,
        byte[]? pinUvAuthToken = null,
        uint pinUvAuthProtocol = 1,
        int maxFragmentLength = DefaultMaxFragmentLength)
    {
        uint offset = 0;

        while (offset < serializedLargeBlobArray.Length)
        {
            int fragmentLength = Math.Min(maxFragmentLength, serializedLargeBlobArray.Length - (int)offset);
            var fragment = serializedLargeBlobArray.AsSpan((int)offset, fragmentLength).ToArray();

            byte[]? pinUvAuthParam = pinUvAuthToken != null
                ? ComputeLargeBlobsPinUvAuthParam(pinUvAuthToken, offset, fragment, pinUvAuthProtocol)
                : null;

            var command = new AuthenticatorLargeBlobsCommand(
                offset,
                set: fragment,
                length: offset == 0 ? serializedLargeBlobArray.Length : null,
                pinUvAuthParam: pinUvAuthParam,
                pinUvAuthProtocol: pinUvAuthParam != null ? pinUvAuthProtocol : null);

            _ = await ExecuteLargeBlobsCommandAsync(command).ConfigureAwait(false);

            offset += (uint)fragmentLength;
        }
    }

    /// <summary>
    /// Computes the pinUvAuthParam for an authenticatorLargeBlobs write fragment:
    /// <c>authenticate(pinUvAuthToken, 32×0xff || h'0c00' || uint32LittleEndian(offset) || SHA-256(set))</c>.
    /// </summary>
    private static byte[] ComputeLargeBlobsPinUvAuthParam(byte[] pinUvAuthToken, uint offset, byte[] set, uint pinUvAuthProtocol)
    {
        Span<byte> message = stackalloc byte[32 + 2 + 4 + 32];
        message[..32].Fill(0xff);
        message[32] = 0x0c;
        message[33] = 0x00;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(message.Slice(34, 4), offset);
        SHA256.HashData(set, message.Slice(38, 32));

        return PinUvAuthProtocol.Select(pinUvAuthProtocol).Authenticate(pinUvAuthToken, message);
    }

    // Helper APIs --

    public async ValueTask<int> GetRetriesAsync()
    {
        var command = new AuthenticatorClientPinCommand(pinUvAuthProtocol: 0x01, subCommand: AuthenticatorClientPinSubCommand.GetPinRetries);

        var result = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);

        return result.PinRetries!.Value;
    }

    /// <param name="newPinUnicode">The new PIN, as UTF-16.</param>
    /// <param name="platformKey">The platform key-agreement key returned by <see cref="NegotiateSharedSecretAsync"/>.</param>
    /// <param name="sharedSecret">The shared secret returned by <see cref="NegotiateSharedSecretAsync"/>.</param>
    /// <param name="protocol">
    /// The PIN/UV auth protocol <paramref name="sharedSecret"/> was negotiated with (see
    /// <see cref="NegotiateSharedSecretAsync"/>). Defaults to <see cref="PinUvAuthProtocolOne"/>.
    /// </param>
    public async ValueTask SetNewPinAsync(string newPinUnicode, CredentialPublicKey platformKey, byte[] sharedSecret, IPinUvAuthProtocol? protocol = null)
    {
        ArgumentNullException.ThrowIfNull(newPinUnicode);

        protocol ??= PinUvAuthProtocolOne.Instance;

        var newPin = Encoding.UTF8.GetBytes(newPinUnicode);

        if (newPin.Length < 4)
        {
            throw new ArgumentException("Must be at least 4 bytes", nameof(newPinUnicode));
        }

        // encrypt(sharedSecret, paddedPin), paddedPin = newPin zero-padded to 64 bytes.
        byte[] newPinEnc = protocol.Encrypt(sharedSecret, CryptoHelper.ZeroPadRight(newPin, 64));

        // authenticate(sharedSecret, newPinEnc)
        var pinUvAuthParam = protocol.Authenticate(sharedSecret, newPinEnc);

        var command = new AuthenticatorClientPinCommand(
            pinUvAuthProtocol: (uint)protocol.Version,
            subCommand: AuthenticatorClientPinSubCommand.SetPin,
            keyAgreement: platformKey,
            pinUvAuthParam: pinUvAuthParam,
            newPinEnc: newPinEnc
        );

        _ = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);
    }

    /// <param name="curPinUnicode">The current PIN, as UTF-16.</param>
    /// <param name="newPinUnicode">The new PIN, as UTF-16.</param>
    /// <param name="platformKey">The platform key-agreement key returned by <see cref="NegotiateSharedSecretAsync"/>.</param>
    /// <param name="sharedSecret">The shared secret returned by <see cref="NegotiateSharedSecretAsync"/>.</param>
    /// <param name="protocol">
    /// The PIN/UV auth protocol <paramref name="sharedSecret"/> was negotiated with (see
    /// <see cref="NegotiateSharedSecretAsync"/>). Defaults to <see cref="PinUvAuthProtocolOne"/>.
    /// </param>
    public async ValueTask ChangePinAsync(string curPinUnicode, string newPinUnicode, CredentialPublicKey platformKey, byte[] sharedSecret, IPinUvAuthProtocol? protocol = null)
    {
        ArgumentNullException.ThrowIfNull(newPinUnicode);

        protocol ??= PinUvAuthProtocolOne.Instance;

        var curPin = Encoding.UTF8.GetBytes(curPinUnicode);
        var newPin = Encoding.UTF8.GetBytes(newPinUnicode);

        if (newPin.Length < 4)
        {
            throw new ArgumentException("Must be at least 4 bytes", nameof(newPinUnicode));
        }

        // encrypt(sharedSecret, LEFT(SHA-256(curPin), 16)).
        byte[] pinHashEnc = protocol.Encrypt(sharedSecret, SHA256.HashData(curPin).AsSpan(0, 16));

        // encrypt(sharedSecret, paddedPin), paddedPin = newPin zero-padded to 64 bytes.
        byte[] newPinEnc = protocol.Encrypt(sharedSecret, CryptoHelper.ZeroPadRight(newPin, 64));

        // authenticate(sharedSecret, newPinEnc || pinHashEnc)
        byte[] pinUvAuthParam = protocol.Authenticate(sharedSecret, [.. newPinEnc, .. pinHashEnc]);

        var command = new AuthenticatorClientPinCommand(
            pinUvAuthProtocol: (uint)protocol.Version,
            subCommand: AuthenticatorClientPinSubCommand.ChangePin,
            keyAgreement: platformKey,
            pinUvAuthParam: pinUvAuthParam,
            newPinEnc: newPinEnc,
            pinHashEnc: pinHashEnc
        );

        _ = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);
    }

    /// <param name="pin">The current PIN, as UTF-16.</param>
    /// <param name="platformKey">The platform key-agreement key returned by <see cref="NegotiateSharedSecretAsync"/>.</param>
    /// <param name="sharedSecret">The shared secret returned by <see cref="NegotiateSharedSecretAsync"/>.</param>
    /// <param name="protocol">
    /// The PIN/UV auth protocol <paramref name="sharedSecret"/> was negotiated with (see
    /// <see cref="NegotiateSharedSecretAsync"/>). Defaults to <see cref="PinUvAuthProtocolOne"/>.
    /// </param>
    public async ValueTask<byte[]> GetPinTokenAsync(string pin, CredentialPublicKey platformKey, byte[] sharedSecret, IPinUvAuthProtocol? protocol = null)
    {
        ArgumentNullException.ThrowIfNull(pin);

        protocol ??= PinUvAuthProtocolOne.Instance;

        byte[] curPin = Encoding.UTF8.GetBytes(pin);

        // encrypt(sharedSecret, LEFT(SHA-256(PIN), 16)).
        byte[] pinHashEnc = protocol.Encrypt(sharedSecret, SHA256.HashData(curPin).AsSpan(0, 16));

        var command = new AuthenticatorClientPinCommand(
            pinUvAuthProtocol: (uint)protocol.Version,
            subCommand: AuthenticatorClientPinSubCommand.GetPinToken,
            keyAgreement: platformKey,
            pinHashEnc: pinHashEnc
        );

        var result = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);

        return result.PinUvAuthToken!;
    }

    /// <summary>
    /// Gets the number of built-in user verification attempts remaining before it is disabled.
    /// </summary>
    public async ValueTask<int> GetUVRetriesAsync()
    {
        var command = new AuthenticatorClientPinCommand(pinUvAuthProtocol: 0x01, subCommand: AuthenticatorClientPinSubCommand.GetUVRetries);

        var result = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);

        return result.UVRetries!.Value;
    }

    /// <summary>
    /// Obtains a pinUvAuthToken scoped to specific permissions using the getPinUvAuthTokenUsingPinWithPermissions
    /// sub command (CTAP 2.1+), superseding the unscoped, permission-less <see cref="GetPinTokenAsync"/>.
    /// </summary>
    /// <param name="pin">The current PIN, as UTF-16.</param>
    /// <param name="platformKey">The platform key-agreement key returned by <see cref="NegotiateSharedSecretAsync"/>.</param>
    /// <param name="sharedSecret">The shared secret returned by <see cref="NegotiateSharedSecretAsync"/>.</param>
    /// <param name="permissions">
    /// The permissions to grant the returned pinUvAuthToken. Request only what is actually needed.
    /// </param>
    /// <param name="rpId">
    /// The permissions RP ID to associate with the token. Required when requesting
    /// <see cref="PinUvAuthTokenPermissions.MakeCredential"/> or <see cref="PinUvAuthTokenPermissions.GetAssertion"/>;
    /// optional (and scoping) for <see cref="PinUvAuthTokenPermissions.CredentialManagement"/>; ignored for the rest.
    /// </param>
    /// <param name="protocol">
    /// The PIN/UV auth protocol <paramref name="sharedSecret"/> was negotiated with (see
    /// <see cref="NegotiateSharedSecretAsync"/>). Defaults to <see cref="PinUvAuthProtocolOne"/>.
    /// </param>
    public async ValueTask<byte[]> GetPinUvAuthTokenUsingPinWithPermissionsAsync(
        string pin,
        CredentialPublicKey platformKey,
        byte[] sharedSecret,
        PinUvAuthTokenPermissions permissions,
        string? rpId = null,
        IPinUvAuthProtocol? protocol = null)
    {
        ArgumentNullException.ThrowIfNull(pin);

        protocol ??= PinUvAuthProtocolOne.Instance;

        byte[] curPin = Encoding.UTF8.GetBytes(pin);

        // encrypt(sharedSecret, LEFT(SHA-256(PIN), 16)).
        byte[] pinHashEnc = protocol.Encrypt(sharedSecret, SHA256.HashData(curPin).AsSpan(0, 16));

        var command = new AuthenticatorClientPinCommand(
            pinUvAuthProtocol: (uint)protocol.Version,
            subCommand: AuthenticatorClientPinSubCommand.GetPinUvAuthTokenUsingPinWithPermissions,
            keyAgreement: platformKey,
            pinHashEnc: pinHashEnc,
            permissions: permissions,
            rpId: rpId
        );

        var result = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);

        return result.PinUvAuthToken!;
    }

    /// <summary>
    /// Obtains a pinUvAuthToken scoped to specific permissions using the getPinUvAuthTokenUsingUvWithPermissions
    /// sub command (CTAP 2.1+), via the authenticator's built-in user verification (e.g. fingerprint)
    /// rather than a PIN.
    /// </summary>
    /// <param name="platformKey">The platform key-agreement key returned by <see cref="NegotiateSharedSecretAsync"/>.</param>
    /// <param name="permissions">
    /// The permissions to grant the returned pinUvAuthToken. Request only what is actually needed.
    /// </param>
    /// <param name="rpId">
    /// The permissions RP ID to associate with the token. Required when requesting
    /// <see cref="PinUvAuthTokenPermissions.MakeCredential"/> or <see cref="PinUvAuthTokenPermissions.GetAssertion"/>;
    /// optional (and scoping) for <see cref="PinUvAuthTokenPermissions.CredentialManagement"/>; ignored for the rest.
    /// </param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version chosen when obtaining the shared secret.</param>
    public async ValueTask<byte[]> GetPinUvAuthTokenUsingUvWithPermissionsAsync(
        CredentialPublicKey platformKey,
        PinUvAuthTokenPermissions permissions,
        string? rpId = null,
        uint pinUvAuthProtocol = 1)
    {
        var command = new AuthenticatorClientPinCommand(
            pinUvAuthProtocol: pinUvAuthProtocol,
            subCommand: AuthenticatorClientPinSubCommand.GetPinUvAuthTokenUsingUvWithPermissions,
            keyAgreement: platformKey,
            permissions: permissions,
            rpId: rpId
        );

        var result = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);

        return result.PinUvAuthToken!;
    }

    /// <summary>
    /// Invokes the authenticatorConfig enableEnterpriseAttestation sub command, permanently
    /// enabling enterprise attestation on the authenticator.
    /// </summary>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>acfg</c> permission.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask EnableEnterpriseAttestationAsync(byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorConfigSubCommand.EnableEnterpriseAttestation;

        var pinUvAuthParam = ComputeConfigPinUvAuthParam(pinUvAuthToken, subCommand, subCommandParams: null, pinUvAuthProtocol);

        var command = new AuthenticatorConfigCommand(subCommand, pinUvAuthProtocol: pinUvAuthProtocol, pinUvAuthParam: pinUvAuthParam);

        _ = await ExecuteConfigCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorConfig toggleAlwaysUv sub command, flipping the authenticator's
    /// "always require user verification" setting.
    /// </summary>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>acfg</c> permission.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask ToggleAlwaysUvAsync(byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorConfigSubCommand.ToggleAlwaysUv;

        var pinUvAuthParam = ComputeConfigPinUvAuthParam(pinUvAuthToken, subCommand, subCommandParams: null, pinUvAuthProtocol);

        var command = new AuthenticatorConfigCommand(subCommand, pinUvAuthProtocol: pinUvAuthProtocol, pinUvAuthParam: pinUvAuthParam);

        _ = await ExecuteConfigCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorConfig enableLongTouchForReset sub command, requiring a touch of
    /// at least 5 seconds for a subsequent authenticatorReset to succeed.
    /// <para>New in CTAP 2.3.</para>
    /// </summary>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>acfg</c> permission.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask EnableLongTouchForResetAsync(byte[] pinUvAuthToken, uint pinUvAuthProtocol = 1)
    {
        var subCommand = AuthenticatorConfigSubCommand.EnableLongTouchForReset;

        var pinUvAuthParam = ComputeConfigPinUvAuthParam(pinUvAuthToken, subCommand, subCommandParams: null, pinUvAuthProtocol);

        var command = new AuthenticatorConfigCommand(subCommand, pinUvAuthProtocol: pinUvAuthProtocol, pinUvAuthParam: pinUvAuthParam);

        _ = await ExecuteConfigCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the authenticatorConfig setMinPINLength sub command, updating the authenticator's
    /// minimum PIN length policy and/or the set of RP IDs allowed to read it via the
    /// <c>minPinLength</c> extension.
    /// </summary>
    /// <param name="newMinPinLength">The new minimum PIN length, in Unicode code points, or <c>null</c> to leave unchanged.</param>
    /// <param name="minPinLengthRpIds">RP IDs to add to the authenticator's minPinLength allow-list, or <c>null</c> to leave unchanged.</param>
    /// <param name="forceChangePin">If <c>true</c>, the authenticator will require the PIN to be changed before it can be used again.</param>
    /// <param name="pinComplexityPolicy">
    /// If <c>true</c>, the authenticator enforces a PIN complexity policy until it is reset.
    /// <para>New in CTAP 2.3.</para>
    /// </param>
    /// <param name="pinUvAuthToken">A pinUvAuthToken obtained with the <c>acfg</c> permission.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol version <paramref name="pinUvAuthToken"/> was obtained with.</param>
    public async ValueTask SetMinPinLengthAsync(
        int? newMinPinLength,
        string[]? minPinLengthRpIds,
        bool? forceChangePin,
        byte[] pinUvAuthToken,
        uint pinUvAuthProtocol = 1,
        bool? pinComplexityPolicy = null)
    {
        var subCommand = AuthenticatorConfigSubCommand.SetMinPinLength;

        CborMap? subCommandParams = null;

        if (newMinPinLength.HasValue || minPinLengthRpIds != null || forceChangePin.HasValue || pinComplexityPolicy.HasValue)
        {
            subCommandParams = new CborMap();

            if (newMinPinLength.HasValue)
            {
                subCommandParams.Add(0x01, newMinPinLength.Value);
            }

            if (minPinLengthRpIds != null)
            {
                var rpIds = new CborArray();
                foreach (var rpId in minPinLengthRpIds)
                {
                    rpIds.Add(rpId);
                }
                subCommandParams.Add(0x02, rpIds);
            }

            if (forceChangePin.HasValue)
            {
                subCommandParams.Add(0x03, (CborObject)(CborBoolean)forceChangePin.Value);
            }

            if (pinComplexityPolicy.HasValue)
            {
                subCommandParams.Add(0x04, (CborObject)(CborBoolean)pinComplexityPolicy.Value);
            }
        }

        var pinUvAuthParam = ComputeConfigPinUvAuthParam(pinUvAuthToken, subCommand, subCommandParams, pinUvAuthProtocol);

        var command = new AuthenticatorConfigCommand(subCommand, subCommandParams, pinUvAuthProtocol, pinUvAuthParam);

        _ = await ExecuteConfigCommandAsync(command).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes the pinUvAuthParam for an authenticatorConfig request:
    /// <c>authenticate(pinUvAuthToken, 32×0xff || 0x0D || subCommand || subCommandParams)</c>,
    /// where <c>subCommandParams</c> is only included, CBOR-encoded, when present.
    /// </summary>
    private static byte[] ComputeConfigPinUvAuthParam(byte[] pinUvAuthToken, AuthenticatorConfigSubCommand subCommand, CborMap? subCommandParams, uint pinUvAuthProtocol)
    {
        byte[] encodedParams = subCommandParams?.Encode() ?? [];

        var message = new byte[34 + encodedParams.Length];
        message.AsSpan(0, 32).Fill(0xff);
        message[32] = (byte)CtapCommandType.AuthenticatorConfig;
        message[33] = (byte)subCommand;
        encodedParams.CopyTo(message.AsSpan(34));

        return PinUvAuthProtocol.Select(pinUvAuthProtocol).Authenticate(pinUvAuthToken, message);
    }

    /// <param name="protocol">
    /// The PIN/UV auth protocol to negotiate a shared secret for. Defaults to <see cref="PinUvAuthProtocolOne"/>;
    /// pass <see cref="PinUvAuthProtocolTwo.Instance"/> for FIPS-oriented authenticators that support it.
    /// </param>
    public async ValueTask<NegotiateSharedSecretResult> NegotiateSharedSecretAsync(IPinUvAuthProtocol? protocol = null)
    {
        protocol ??= PinUvAuthProtocolOne.Instance;

        var command = new AuthenticatorClientPinCommand(pinUvAuthProtocol: (uint)protocol.Version, subCommand: AuthenticatorClientPinSubCommand.GetKeyAgreement);

        var result = await ExecuteClientPinCommandAsync(command).ConfigureAwait(false);

        var authenticatorKey = result.KeyAgreement!;

        byte[] sharedSecret = protocol.GenerateSharedSecret(authenticatorKey, out var platformKey);

        return new NegotiateSharedSecretResult(authenticatorKey, platformKey, sharedSecret);
    }

    protected abstract ValueTask<FidoAuthenticatorResponse> ExecuteCommandAsync(CtapCommand command);
}
