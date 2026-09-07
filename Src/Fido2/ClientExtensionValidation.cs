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
    /// Validates PRF extension input structure.
    /// Ensures eval inputs have proper format and constraints.
    /// </summary>
    internal static void ValidatePRFInput(AuthenticationExtensionsPRFInputs prfInput)
    {
        // PRF input must have eval or evalByCredential (or both)
        if (prfInput.Eval == null && prfInput.EvalByCredential == null)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "PRF extension input must have 'eval' or 'evalByCredential'");
        }

        // Validate eval if present
        if (prfInput.Eval != null)
        {
            ValidatePRFInputValues(prfInput.Eval, "eval");
        }

        // Validate evalByCredential if present
        if (prfInput.EvalByCredential.HasValue)
        {
            var evalByCred = prfInput.EvalByCredential.Value;
            // Credential ID should be non-empty
            if (string.IsNullOrEmpty(evalByCred.Key))
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    "PRF extension 'evalByCredential' has empty credential ID");
            }
            // Credential values should be valid
            ValidatePRFInputValues(evalByCred.Value, "evalByCredential");
        }
    }

    /// <summary>
    /// Validates PRF input values (first and optional second salts).
    /// </summary>
    private static void ValidatePRFInputValues(AuthenticationExtensionsPRFValues values, string fieldName)
    {
        // First value is required
        if (values.First == null || values.First.Length == 0)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                $"PRF extension '{fieldName}' has missing or empty 'first' value");
        }

        // PRF inputs are typically 32 bytes but allow flexibility
        if (values.First.Length < 16 || values.First.Length > 512)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                $"PRF extension '{fieldName}' 'first' value has unexpected length: {values.First.Length}. Expected 16-512 bytes.");
        }

        // Second value is optional, but if present should have reasonable length
        if (values.Second != null && values.Second.Length > 0)
        {
            if (values.Second.Length < 16 || values.Second.Length > 512)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"PRF extension '{fieldName}' 'second' value has unexpected length: {values.Second.Length}. Expected 16-512 bytes.");
            }
        }
    }

    /// <summary>
    /// Validates PRF extension output format per WebAuthn L3 Section 9.
    /// https://w3c.github.io/webauthn/#prf-extension
    /// </summary>
    internal static void ValidatePRFOutput(AuthenticationExtensionsPRFOutputs prfOutput)
    {
        // If enabled is false, results must not be present
        if (!prfOutput.Enabled && prfOutput.Results != null)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "PRF extension output has enabled=false but results are present");
        }

        // If enabled is true and results are present, validate the results format
        if (prfOutput.Enabled && prfOutput.Results != null)
        {
            ValidatePRFValues(prfOutput.Results);
        }
    }

    /// <summary>
    /// Validates PRF values (first and second salts).
    /// Both first and second should be byte arrays of appropriate length.
    /// </summary>
    private static void ValidatePRFValues(AuthenticationExtensionsPRFValues values)
    {
        // First value is required
        if (values.First == null || values.First.Length == 0)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "PRF extension output has missing or empty 'first' value");
        }

        // PRF output should be 32 bytes (SHA-256 output) or 64 bytes
        // Allow flexibility for different PRF implementations
        if (values.First.Length != 32 && values.First.Length != 64)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                $"PRF extension 'first' value has unexpected length: {values.First.Length}. Expected 32 or 64 bytes.");
        }

        // Second value is optional, but if present should have same length as first
        if (values.Second != null && values.Second.Length > 0)
        {
            if (values.Second.Length != values.First.Length)
            {
                throw new Fido2VerificationException(
                    Fido2ErrorCode.MalformedExtensionsDetected,
                    $"PRF extension 'second' value length ({values.Second.Length}) does not match 'first' value length ({values.First.Length})");
            }
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
