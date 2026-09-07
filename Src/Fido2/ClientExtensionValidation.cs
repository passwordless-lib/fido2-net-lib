using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Linq;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Validation of the WebAuthn client extension inputs a Relying Party sends and the client extension outputs
/// it gets back, for the parts that both ceremonies share.
/// </summary>
/// <remarks>
/// Ceremony-specific rules stay with the ceremony, in <see cref="AuthenticatorAttestationResponse"/> and
/// <see cref="AuthenticatorAssertionResponse"/>.
/// </remarks>
internal static class ClientExtensionValidation
{
    /// <summary>
    /// The length of a PRF result: "the PRFs provided by this extension map from BufferSources of any length
    /// to 32-byte BufferSources".
    /// </summary>
    private const int PRFResultLength = 32;

    /// <summary>
    /// Validates the <c>prf</c> extension input of a registration ceremony.
    /// </summary>
    /// <remarks>
    /// Both members are optional -- an empty <c>prf</c> input is how a Relying Party asks only whether PRFs
    /// are available -- but <c>evalByCredential</c> is registration-invalid: a client returns a
    /// <c>NotSupportedError</c> for it rather than creating the credential.
    /// <para>
    /// <see href="https://www.w3.org/TR/webauthn-3/#prf-extension"/>
    /// </para>
    /// </remarks>
    internal static void ValidateRegistrationPRFInput(AuthenticationExtensionsPRFInputs prfInput)
    {
        // "If evalByCredential is present, return a DOMException whose name is NotSupportedError."
        if (prfInput.EvalByCredential is not null)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "The prf extension's 'evalByCredential' is not valid during registration. Use 'eval' instead.");
        }

        if (prfInput.Eval is not null)
            ValidatePRFInputValues(prfInput.Eval, "eval");
    }

    /// <summary>
    /// Validates the <c>prf</c> extension input of an authentication ceremony against the
    /// <paramref name="allowCredentials"/> it accompanies.
    /// </summary>
    /// <remarks>
    /// Both members are optional. When <c>evalByCredential</c> is used, a client requires a non-empty
    /// <c>allowCredentials</c> and requires every key to name one of its entries; checking that here turns a
    /// browser-side <c>NotSupportedError</c> or <c>SyntaxError</c> into a diagnosable server-side failure.
    /// <para>
    /// <see href="https://www.w3.org/TR/webauthn-3/#prf-extension"/>
    /// </para>
    /// </remarks>
    internal static void ValidateAssertionPRFInput(
        AuthenticationExtensionsPRFInputs prfInput,
        IReadOnlyList<PublicKeyCredentialDescriptor>? allowCredentials)
    {
        if (prfInput.Eval is not null)
            ValidatePRFInputValues(prfInput.Eval, "eval");

        if (prfInput.EvalByCredential is not { Count: > 0 } evalByCredential)
            return;

        // "If evalByCredential is not empty but allowCredentials is empty, return a DOMException whose name
        //  is NotSupportedError."
        if (allowCredentials is not { Count: > 0 })
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "The prf extension's 'evalByCredential' requires a non-empty allowCredentials.");
        }

        foreach (var (credentialId, values) in evalByCredential)
        {
            // "If any key in evalByCredential is the empty string, or is not a valid base64url encoding, or
            //  does not equal the id of some element of allowCredentials after performing base64url
            //  decoding, then return a DOMException whose name is SyntaxError."
            if (string.IsNullOrEmpty(credentialId))
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    "The prf extension's 'evalByCredential' has an empty credential ID key.");
            }

            byte[] decodedCredentialId;

            try
            {
                decodedCredentialId = Base64Url.DecodeFromChars(credentialId);
            }
            catch (FormatException e)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"The prf extension's 'evalByCredential' key '{credentialId}' is not valid base64url.", e);
            }

            if (!allowCredentials.Any(credential => credential.Id.AsSpan().SequenceEqual(decodedCredentialId)))
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"The prf extension's 'evalByCredential' key '{credentialId}' does not match any allowCredentials entry.");
            }

            ValidatePRFInputValues(values, "evalByCredential");
        }
    }

    /// <summary>
    /// Validates one pair of PRF salts.
    /// </summary>
    /// <remarks>
    /// The PRFs "map from BufferSources of any length", so a salt has no length to check against -- the
    /// client hashes it with a context string before it ever reaches an authenticator. Only the presence of
    /// the required member is checked.
    /// </remarks>
    private static void ValidatePRFInputValues(AuthenticationExtensionsPRFValues values, string fieldName)
    {
        if (values.First is null)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                $"The prf extension's '{fieldName}' is missing its required 'first' value.");
        }
    }

    /// <summary>
    /// Validates the <c>prf</c> extension output of a registration ceremony.
    /// </summary>
    /// <remarks>
    /// Client extension processing sets <c>enabled</c> on a registration whether or not PRFs turned out to
    /// be available, so results alongside a <see langword="false"/> are a contradiction. An absent
    /// <c>enabled</c> means the client does not implement the extension at all, which is the Relying Party's
    /// business rather than a malformed response.
    /// </remarks>
    internal static void ValidateRegistrationPRFOutput(AuthenticationExtensionsPRFOutputs prfOutput)
    {
        if (prfOutput.Enabled is false && prfOutput.Results is not null)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "The prf extension output reports enabled=false but carries results.");
        }

        if (prfOutput.Results is not null)
            ValidatePRFResults(prfOutput.Results);
    }

    /// <summary>
    /// Validates the <c>prf</c> extension output of an authentication ceremony.
    /// </summary>
    /// <remarks>
    /// Client extension processing for an assertion initializes the output to an empty dictionary and only
    /// ever sets <c>results</c>, so there is no <c>enabled</c> to reason about here -- the registration rule
    /// must not be applied, or every PRF-carrying assertion fails.
    /// </remarks>
    internal static void ValidateAssertionPRFOutput(AuthenticationExtensionsPRFOutputs prfOutput)
    {
        if (prfOutput.Results is not null)
            ValidatePRFResults(prfOutput.Results);
    }

    /// <summary>
    /// Validates the results of evaluating the PRF, which are 32 bytes each.
    /// </summary>
    private static void ValidatePRFResults(AuthenticationExtensionsPRFValues values)
    {
        if (values.First is null or [])
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "The prf extension output has a missing or empty 'first' value.");
        }

        if (values.First.Length is not PRFResultLength)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                $"The prf extension output's 'first' value is {values.First.Length} bytes; a PRF result is {PRFResultLength} bytes.");
        }

        if (values.Second is { Length: > 0 } second && second.Length is not PRFResultLength)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                $"The prf extension output's 'second' value is {second.Length} bytes; a PRF result is {PRFResultLength} bytes.");
        }
    }

    /// <summary>
    /// Validates extensions discovery (exts) output.
    /// The output should be an array of supported extension identifiers.
    /// </summary>
    internal static void ValidateExtensionsDiscoveryOutput(string[] supportedExtensions)
    {
        if (supportedExtensions == null)
            return;

        // Validate each extension identifier
        foreach (var ext in supportedExtensions)
        {
            if (string.IsNullOrWhiteSpace(ext))
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    "Extension identifier in discovery output is empty or whitespace");
            }

            // Extension identifiers should be reasonable length (typically short strings like "prf", "largeBlob", etc.)
            if (ext.Length > 128)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"Extension identifier '{ext}' is excessively long");
            }
        }
    }
}
