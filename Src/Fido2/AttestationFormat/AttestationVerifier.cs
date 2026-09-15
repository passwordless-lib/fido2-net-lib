using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

public abstract class AttestationVerifier
{
    public ValueTask<VerifyAttestationResult> VerifyAsync(CborMap attStmt, AuthenticatorData authenticatorData, byte[] clientDataHash)
    {
        return VerifyAsync(new VerifyAttestationRequest(attStmt, authenticatorData, clientDataHash));
    }

    public abstract ValueTask<VerifyAttestationResult> VerifyAsync(VerifyAttestationRequest request);

    public static AttestationVerifier Create(string formatIdentifier)
    {
        #pragma warning disable format
        return formatIdentifier switch
        {
            "none"              => new None(),             // https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
            "tpm"               => new Tpm(),              // https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation
            "android-key"       => new AndroidKey(),       // https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
            "android-safetynet" => new AndroidSafetyNet(), // deprecated in L3: https://www.w3.org/TR/webauthn-3/#sctn-android-safetynet-attestation
            "fido-u2f"          => new FidoU2f(),          // https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
            "packed"            => new Packed(),           // https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
            "apple"             => new Apple(),            // https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
            "apple-appattest"   => new AppleAppAttest(),   // https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
            // "compound" carries an array of sub-statements rather than a map, so it does not fit this
            // contract; AuthenticatorAttestationResponse dispatches it to Compound.VerifyAsync instead.
            "compound"          => throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"Compound attestation is not verified through {nameof(AttestationVerifier)}; use {nameof(Compound)}.{nameof(Compound.VerifyAsync)}"),
            _                   => throw new Fido2VerificationException(Fido2ErrorCode.UnknownAttestationType, $"Unknown attestation type. Was '{formatIdentifier}'")
        };
        #pragma warning restore format
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

    internal static byte[]? AaguidFromAttnCertExts(X509ExtensionCollection exts)
    {
        byte[]? aaguid = null;
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

    /// <summary>
    /// Reads the id-fido-gen-ce-sernum extension (OID 1.3.6.1.4.1.45724.1.1.2) from an attestation
    /// certificate, returning <see langword="null"/> when it is absent. The value is a unique octet string per
    /// device against a particular AAGUID, constant across factory resets, and is only permitted in
    /// attestations conveyed for enterprise use.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-enterprise-packed-attestation-cert-requirements"/>
    /// </remarks>
    internal static byte[]? SerialNumberFromAttnCertExts(X509ExtensionCollection exts)
    {
        var ext = exts.FirstOrDefault(static e => e.Oid?.Value is "1.3.6.1.4.1.45724.1.1.2"); // id-fido-gen-ce-sernum
        if (ext is null)
            return null;

        // "This extension MUST NOT be marked as critical, and the corresponding value is encoded as an OCTET STRING."
        if (ext.Critical)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.CriticalEnterpriseAttestationSerialNumber);

        var decodedSerialNumber = Asn1Element.Decode(ext.RawData);
        decodedSerialNumber.CheckTag(Asn1Tag.PrimitiveOctetString);

        byte[] serialNumber = decodedSerialNumber.GetOctetString();

        // "If present, this extension MUST indicate a unique octet string value per device against a particular
        // AAGUID." An empty string cannot identify a device, so treat it as malformed rather than pass it on.
        if (serialNumber.Length is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.EmptyEnterpriseAttestationSerialNumber);

        return serialNumber;
    }

    /// <summary>
    /// Reads the id-fido-gen-ce-fw-version extension (OID 1.3.6.1.4.1.45724.1.1.5) from an attestation
    /// certificate, returning <see langword="null"/> when it is absent. The value differentiates the firmware
    /// of one authenticator model and is incremented for each new firmware release.
    /// </summary>
    /// <remarks>
    /// It is directly comparable with the <c>authenticatorVersion</c> a Metadata Service status report gives
    /// for the same model, which is how a Relying Party can tell that an authenticator is running firmware
    /// older than the one a certification or a fix applies to.
    /// <para>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements"/>
    /// </para>
    /// </remarks>
    internal static ulong? FirmwareVersionFromAttnCertExts(X509ExtensionCollection exts)
    {
        var ext = exts.FirstOrDefault(static e => e.Oid?.Value is "1.3.6.1.4.1.45724.1.1.5"); // id-fido-gen-ce-fw-version
        if (ext is null)
            return null;

        // "The extension MUST NOT be marked as critical."
        if (ext.Critical)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.CriticalFirmwareVersion);

        var decodedFirmwareVersion = Asn1Element.Decode(ext.RawData);
        decodedFirmwareVersion.CheckTag(Asn1Tag.Integer);

        var firmwareVersion = decodedFirmwareVersion.GetBigInteger();

        // "This attribute contains an INTEGER with a non-negative value which is incremented for new firmware
        // release versions." Metadata reports the same quantity as an unsigned 64-bit authenticatorVersion, so
        // anything outside that range cannot be the value this extension is meant to carry.
        if (firmwareVersion.Sign < 0 || firmwareVersion > ulong.MaxValue)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidFirmwareVersion);

        return (ulong)firmwareVersion;
    }

    internal static byte U2FTransportsFromAttnCert(X509ExtensionCollection exts)
    {
        byte u2fTransports = 0;
        var ext = exts.FirstOrDefault(e => e.Oid?.Value is "1.3.6.1.4.1.45724.2.1.1"); // id-fido-u2f-ce-transports
        if (ext != null)
        {
            var decodedU2fTransports = Asn1Element.Decode(ext.RawData);
            decodedU2fTransports.CheckPrimitive();

            // some certificates seem to have this encoded as an octet string
            // instead of a bit string, attempt to correct
            if (decodedU2fTransports.Tag == Asn1Tag.PrimitiveOctetString)
            {
                ext.RawData[0] = (byte)UniversalTagNumber.BitString;
                decodedU2fTransports = Asn1Element.Decode(ext.RawData);
            }

            decodedU2fTransports.CheckTag(Asn1Tag.PrimitiveBitString);

            u2fTransports = decodedU2fTransports.GetBitString()[0];
        }

        return u2fTransports;
    }
}
