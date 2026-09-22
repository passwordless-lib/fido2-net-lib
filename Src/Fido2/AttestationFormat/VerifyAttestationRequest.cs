using System;
using System.Diagnostics.CodeAnalysis;

using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

public sealed class VerifyAttestationRequest(
    CborMap attStmt,
    AuthenticatorData authenticationData,
    byte[] clientDataHash,
    FidoValidationMode validationMode = FidoValidationMode.Default)
{
    private readonly CborMap _attStmt = attStmt;
    private readonly AuthenticatorData _authenticatorData = authenticationData;
    private readonly byte[] _clientDataHash = clientDataHash;
    private readonly FidoValidationMode _validationMode = validationMode;

    internal CborMap AttStmt => _attStmt;

    /// <summary>
    /// How strictly to validate: <see cref="FidoValidationMode.FidoConformance2024"/> when the ceremony is being
    /// driven by the FIDO conformance tools, whose simulated authenticators differ from production ones in a few
    /// documented ways (see <see cref="Tpm.FidoConformanceToolTpmManufacturer"/>); otherwise the default.
    /// </summary>
    internal FidoValidationMode ValidationMode => _validationMode;

    internal ReadOnlySpan<byte> ClientDataHash => _clientDataHash;

    internal CborObject? X5c => _attStmt["x5c"];

    internal CborObject? EcdaaKeyId => _attStmt["ecdaaKeyId"];

    internal AuthenticatorData AuthData => _authenticatorData;

    internal CborMap CredentialPublicKey => AuthData.AttestedCredentialData!.CredentialPublicKey.GetCborObject();

    internal byte[] Data => [.. _authenticatorData.ToByteArray(), .. _clientDataHash];

    internal bool TryGetVer([NotNullWhen(true)] out string? ver)
    {
        if (_attStmt["ver"] is CborTextString { Length: > 0, Value: string verString })
        {
            ver = verString;

            return true;
        }

        ver = null;

        return false;
    }

    internal bool TryGetAlg(out COSE.Algorithm alg)
    {
        if (_attStmt["alg"] is CborInteger algInt)
        {
            alg = (COSE.Algorithm)algInt.Value;

            return true;
        }

        alg = default;

        return false;
    }

    internal bool TryGetSig([NotNullWhen(true)] out byte[]? sig)
    {
        if (_attStmt["sig"] is CborByteString { Length: > 0 } sigBytes)
        {
            sig = sigBytes.Value;

            return true;
        }

        sig = null;

        return false;
    }
}
