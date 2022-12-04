#nullable disable

using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

public abstract class AttestationVerifier
{
    private protected CborMap _attStmt;
    private protected byte[] _authenticatorData;
    private protected byte[] _clientDataHash;

#nullable enable

    internal CborObject? X5c => _attStmt["x5c"];

    internal CborObject? EcdaaKeyId => _attStmt["ecdaaKeyId"];

    internal AuthenticatorData AuthData => new (_authenticatorData);

    internal CborMap CredentialPublicKey => AuthData.AttestedCredentialData.CredentialPublicKey.GetCborObject();

    internal byte[] Data => DataHelper.Concat(_authenticatorData, _clientDataHash);

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

#nullable disable

    internal static byte[] AaguidFromAttnCertExts(X509ExtensionCollection exts)
    {
        byte[] aaguid = null;
        var ext = exts.FirstOrDefault(static e => e.Oid?.Value is "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
        if (ext != null)
        {
            var decodedAaguid = Asn1Element.Decode(ext.RawData);
            decodedAaguid.CheckTag(Asn1Tag.PrimitiveOctetString);
            aaguid = decodedAaguid.GetOctetString();

            // The extension MUST NOT be marked as critical
            if (ext.Critical)
                throw new Fido2VerificationException("extension MUST NOT be marked as critical");
        }

        return aaguid;
    }

    internal static bool IsAttnCertCACert(X509ExtensionCollection exts)
    {
        var ext = exts.FirstOrDefault(static e => e.Oid?.Value is "2.5.29.19");
        if (ext is X509BasicConstraintsExtension baseExt)
        {
            return baseExt.CertificateAuthority;
        }

        return true;
    }

    internal static byte U2FTransportsFromAttnCert(X509ExtensionCollection exts)
    {
        byte u2ftransports = 0;
        var ext = exts.FirstOrDefault(e => e.Oid?.Value is "1.3.6.1.4.1.45724.2.1.1");
        if (ext != null)
        {
            var decodedU2Ftransports = Asn1Element.Decode(ext.RawData);
            decodedU2Ftransports.CheckPrimitive();

            // some certificates seem to have this encoded as an octet string
            // instead of a bit string, attempt to correct
            if (decodedU2Ftransports.Tag == Asn1Tag.PrimitiveOctetString)
            {
                ext.RawData[0] = (byte)UniversalTagNumber.BitString;
                decodedU2Ftransports = Asn1Element.Decode(ext.RawData);
            }

            decodedU2Ftransports.CheckTag(Asn1Tag.PrimitiveBitString);

            u2ftransports = decodedU2Ftransports.GetBitString()[0];
        }

        return u2ftransports;
    }

    public virtual (AttestationType, X509Certificate2[]) Verify(CborMap attStmt, byte[] authenticatorData, byte[] clientDataHash)
    {
        _attStmt = attStmt;
        _authenticatorData = authenticatorData;
        _clientDataHash = clientDataHash;
        return Verify();
    }

    public abstract (AttestationType, X509Certificate2[]) Verify();

    public static AttestationVerifier Create(string formatIdentifier)
    {
        return formatIdentifier switch
        {
            "none"              => new None(),             // https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
            "tpm"               => new Tpm(),              // https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation
            "android-key"       => new AndroidKey(),       // https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
            "android-safetynet" => new AndroidSafetyNet(), // https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation
            "fido-u2f"          => new FidoU2f(),          // https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
            "packed"            => new Packed(),           // https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
            "apple"             => new Apple(),            // https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
            "apple-appattest"   => new AppleAppAttest(),   // https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server  
            _                   => throw new Fido2VerificationException(Fido2ErrorCode.UnknownAttestationType, $"Unknown attestation type. Was '{formatIdentifier}'")
        };
    }
}
