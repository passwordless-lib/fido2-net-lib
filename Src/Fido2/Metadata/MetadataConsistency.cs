using System;
using System.Collections.Generic;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// Shared helpers for the checks <see cref="Fido2Configuration.MetadataConsistencyStrictness"/> gates, used by
/// both <see cref="AuthenticatorAttestationResponse"/> (registration-time checks) and
/// <see cref="AuthenticatorAssertionResponse"/> (assertion-time checks -- see its own remarks for which checks
/// apply there and, as importantly, which WebAuthn simply does not give a Relying Party the information to make
/// at assertion time at all).
/// </summary>
internal static class MetadataConsistency
{
    /// <summary>
    /// A WebAuthn extension output identifier paired with the identifier the same capability is declared under
    /// in a FIDO2 metadata statement (<c>supportedExtensions</c> and <c>authenticatorGetInfo.extensions</c> both
    /// use CTAP2 identifiers, which differ from the WebAuthn client extension output name for two of these).
    /// Deliberately narrow: only extensions with an output that is itself evidence of an authenticator-level
    /// capability are listed. Client-only outputs an authenticator statement would never declare
    /// (<c>credProps</c>, the deprecated L2 <c>exts</c>/<c>uvm</c>) are excluded on purpose, not by oversight.
    /// </summary>
    public static readonly (string WebAuthnId, string MetadataId)[] AuthenticatorLevelExtensions =
    [
        ("credProtect", "credProtect"),
        ("credBlob", "credBlob"),
        ("minPinLength", "minPinLength"),
        ("prf", "hmac-secret"),
        ("largeBlob", "largeBlobKey"),
    ];

    /// <summary>
    /// Logs a metadata-consistency mismatch (always), then, if <paramref name="strictness"/> and
    /// <paramref name="strong"/> together call for it, logs that it is blocking the ceremony and throws.
    /// A weak-tier mismatch only blocks at <see cref="MetadataConsistencyStrictness.Strict"/>; a strong-tier
    /// mismatch blocks at <see cref="MetadataConsistencyStrictness.Standard"/> and above.
    /// </summary>
    public static void ReportMismatch(
        MetadataConsistencyStrictness strictness, bool strong,
        Fido2ErrorCode code, string message,
        string check, Guid aaguid, string detail,
        ILogger? logger)
    {
        logger?.MetadataConsistencyMismatchObserved(check, aaguid, detail);

        var blocks = strictness is MetadataConsistencyStrictness.Strict || (strictness is MetadataConsistencyStrictness.Standard && strong);
        if (!blocks)
            return;

        logger?.MetadataConsistencyMismatchBlocked(check, aaguid, detail);
        throw new Fido2VerificationException(code, message);
    }

    /// <summary>
    /// Extracts the set of extension identifiers from a client extension results object -- shared between
    /// registration and assertion since both carry the same <see cref="AuthenticationExtensionsClientOutputs"/> shape.
    /// </summary>
    public static HashSet<string> GetClientExtensionResultIdentifiers(AuthenticationExtensionsClientOutputs clientExtensionResults)
    {
        var identifiers = new HashSet<string>(StringComparer.Ordinal);

        if (clientExtensionResults.Example.HasValue)
            identifiers.Add("example.extension.bool");

#pragma warning disable CS0618 // uvm and exts were removed in L3; still honoured for Level 2 callers
        if (clientExtensionResults.Extensions != null && clientExtensionResults.Extensions.Length > 0)
            identifiers.Add("exts");

        if (clientExtensionResults.UserVerificationMethod != null && clientExtensionResults.UserVerificationMethod.Length > 0)
            identifiers.Add("uvm");
#pragma warning restore CS0618

        if (clientExtensionResults.CredProps != null)
            identifiers.Add("credProps");

        if (clientExtensionResults.PRF != null)
            identifiers.Add("prf");

        if (clientExtensionResults.LargeBlob != null)
            identifiers.Add("largeBlob");

        if (clientExtensionResults.CredBlob.HasValue)
            identifiers.Add("credBlob");

        if (clientExtensionResults.CredProtect.HasValue)
            identifiers.Add("credProtect");

        // Note: credProtect is the output for credentialProtectionPolicy input
        if (clientExtensionResults.CredProtect.HasValue)
            identifiers.Add("credentialProtectionPolicy");

        if (clientExtensionResults.AppIDExclude)
            identifiers.Add("appidExclude");

        if (clientExtensionResults.MinPinLength.HasValue)
            identifiers.Add("minPinLength");

        return identifiers;
    }
}
