using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Verifies the <c>compound</c> attestation statement format, which carries two or more self-contained
/// attestation statements for the same credential in a single ceremony.
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation"/>
/// </summary>
/// <remarks>
/// Unlike every other defined format, a compound statement's <c>attStmt</c> is a CBOR array rather than a map,
/// so it does not fit the <see cref="AttestationVerifier"/> contract and is dispatched separately by
/// <see cref="AuthenticatorAttestationResponse"/>.
/// </remarks>
public static class Compound
{
    /// <summary>
    /// The attestation statement format identifier for compound attestation.
    /// </summary>
    public const string FormatIdentifier = "compound";

    /// <summary>
    /// The minimum number of sub-statements a compound attestation statement must contain, per the CDDL
    /// <c>attStmt: [2* nonCompoundAttStmt]</c>.
    /// </summary>
    public const int MinimumSubStatements = 2;

    /// <summary>
    /// Runs the verification procedure of every sub-statement and reduces the outcomes to a single result
    /// according to <paramref name="policy"/>.
    /// </summary>
    /// <returns>
    /// The result of the first sub-statement that verified successfully and conveyed an attestation type other
    /// than <see cref="AttestationType.None"/>, falling back to the first successful result. Sub-statements are
    /// considered in the order the authenticator listed them.
    /// </returns>
    /// <exception cref="Fido2VerificationException">
    /// Thrown when the statement is malformed, or when too few sub-statements verified to satisfy
    /// <paramref name="policy"/>.
    /// </exception>
    public static async ValueTask<VerifyAttestationResult> VerifyAsync(
        CborArray attStmt,
        AuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CompoundAttestationPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(attStmt);

        if (attStmt.Length < MinimumSubStatements)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.InvalidAttestation,
                $"Compound attestation statement must contain at least {MinimumSubStatements} sub-statements, found {attStmt.Length}");
        }

        List<VerifyAttestationResult> successes = [];
        List<string> failures = [];

        foreach (var subStatement in attStmt)
        {
            var (fmt, subAttStmt) = ParseSubStatement(subStatement);

            try
            {
                successes.Add(await AttestationVerifier.Create(fmt).VerifyAsync(subAttStmt, authenticatorData, clientDataHash).ConfigureAwait(false));
            }
            catch (Fido2VerificationException e)
            {
                failures.Add($"'{fmt}': {e.Message}");
            }
        }

        var required = policy is CompoundAttestationPolicy.RequireAll ? attStmt.Length : 1;

        if (successes.Count < required)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.InvalidAttestation,
                $"Compound attestation required {required} of {attStmt.Length} sub-statements to verify, but only {successes.Count} did. Failures: {string.Join("; ", failures)}");
        }

        // "Return implementation-specific values representing any combination of outputs from successful
        // verification procedures." A single (type, trust path) pair has to be reported onwards, and a pair drawn
        // from one sub-statement stays internally consistent, whereas merging trust paths across formats would
        // produce a chain that no single verification procedure actually vouched for. Prefer a sub-statement that
        // conveys real attestation over one that conveys none.
        foreach (var success in successes)
        {
            if (success.Type != AttestationType.None)
                return success;
        }

        return successes[0];
    }

    private static (string Fmt, CborMap AttStmt) ParseSubStatement(CborObject subStatement)
    {
        if (subStatement is not CborMap map)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.InvalidAttestation,
                "Compound attestation sub-statement must be a CBOR map");
        }

        if (map["fmt"] is not CborTextString fmt)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.InvalidAttestation,
                "Compound attestation sub-statement is missing a 'fmt' text string");
        }

        // nonCompoundAttStmt = { $$attStmtType } .within { fmt: text .ne "compound", * any => any }
        if (fmt.Value is FormatIdentifier)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.InvalidAttestation,
                "Compound attestation statements may not be nested");
        }

        if (map["attStmt"] is not CborMap subAttStmt)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.InvalidAttestation,
                $"Compound attestation sub-statement '{fmt.Value}' is missing an 'attStmt' map");
        }

        return (fmt.Value, subAttStmt);
    }
}
