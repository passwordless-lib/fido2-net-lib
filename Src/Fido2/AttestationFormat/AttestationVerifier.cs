using System;
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

    public ValueTask<VerifyAttestationResult> VerifyAsync(CborMap attStmt, AuthenticatorData authenticatorData, byte[] clientDataHash, FidoValidationMode validationMode)
    {
        return VerifyAsync(new VerifyAttestationRequest(attStmt, authenticatorData, clientDataHash, validationMode));
    }

    public abstract ValueTask<VerifyAttestationResult> VerifyAsync(VerifyAttestationRequest request);

    public static AttestationVerifier Create(string formatIdentifier, Fido2Configuration config)
    {
        #pragma warning disable format
        return formatIdentifier switch
        {
            "none"              => new None(),             // https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
            "tpm"               => new Tpm(),              // https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation
            "android-key"       => new AndroidKey(),       // https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
            "android-safetynet" => new AndroidSafetyNet(config?.AndroidSafetyNetRootCertificate ?? AndroidSafetyNet.GtsRootR1), // https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation
            "fido-u2f"          => new FidoU2f(),          // https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
            "packed"            => new Packed(),           // https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
            "apple"             => new Apple(config?.AppleWebAuthnRootCertificate ?? Apple.AppleWebAuthnRootCA), // https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
            "apple-appattest"   => new AppleAppAttest(),   // https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
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
            Asn1Element decodedAaguid;
            try
            {
                decodedAaguid = Asn1Element.Decode(ext.RawData);
                decodedAaguid.CheckTag(Asn1Tag.PrimitiveOctetString);
            }
            catch (Exception ex)
            {
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "id-fido-gen-ce-aaguid extension is not an OCTET STRING", ex);
            }

            aaguid = decodedAaguid.GetOctetString();

            // ... containing the AAGUID as a 16-byte OCTET STRING; anything else cannot be compared with the
            // authenticator data's AAGUID (and would make the Guid constructor throw)
            if (aaguid.Length != 16)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"id-fido-gen-ce-aaguid extension must be a 16-byte OCTET STRING, got {aaguid.Length} bytes");

            // The extension MUST NOT be marked as critical
            if (ext.Critical)
                throw new Fido2VerificationException("extension MUST NOT be marked as critical");
        }

        return aaguid;
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
