using System;
using System.Diagnostics.CodeAnalysis;

using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

public sealed class VerifyAttestationRequest
{
    private readonly CborMap _attStmt;
    private readonly AuthenticatorData _authenticatorData;
    private readonly byte[] _clientDataHash;

    public VerifyAttestationRequest(CborMap attStmt, AuthenticatorData authenticationData, byte[] clientDataHash)
    {
        _attStmt = attStmt;
        _authenticatorData = authenticationData;
        _clientDataHash = clientDataHash;
    }

    internal CborMap AttStmt => _attStmt;

    internal ReadOnlySpan<byte> ClientDataHash => _clientDataHash;

    internal CborObject? X5c => _attStmt["x5c"];

    internal CborObject? EcdaaKeyId => _attStmt["ecdaaKeyId"];

    internal AuthenticatorData AuthData => _authenticatorData;

    internal CborMap CredentialPublicKey => AuthData.AttestedCredentialData!.CredentialPublicKey.GetCborObject();

    internal byte[] Data => DataHelper.Concat(_authenticatorData.ToByteArray(), _clientDataHash);

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
