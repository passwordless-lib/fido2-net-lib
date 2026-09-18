using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

internal sealed class Tpm : AttestationVerifier
{
    private static string ConvertTPMManufacturerToHexString(string id) => BitConverter.ToString(Convert.FromHexString(id.Split(':')[^1])).Replace("-", "");

    /// <summary>
    /// Converts a tcg-at-tpmManufacturer value ("id:" followed by the vendor ID as hex) to the canonical
    /// upper-case hex form used by <see cref="TPMManufacturers"/>, or returns <see langword="null"/> when the
    /// value is not of that form. The value comes from an attacker-supplied certificate, so a malformed one
    /// must not surface as a FormatException.
    /// </summary>
    private static string? TryConvertTPMManufacturerToHexString(string id)
    {
        var hex = id.Split(':')[^1];

        if (hex.Length is 0 || hex.Length % 2 != 0)
            return null;

        try
        {
            return ConvertTPMManufacturerToHexString(id);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// The tcg-at-tpmManufacturer value ("id:FFFFF1D0", in the form <see cref="TPMManufacturers"/> uses) of the
    /// FIDO conformance tools' simulated TPM. It is not a TCG-registered vendor, so it is accepted only when the
    /// ceremony is running under <see cref="FidoValidationMode.FidoConformance2024"/>; a production registration
    /// whose AIK certificate names it is refused like any other unregistered manufacturer.
    /// </summary>
    internal static readonly string FidoConformanceToolTpmManufacturer = ConvertTPMManufacturerToHexString("id:FFFFF1D0");

    /// <summary>
    /// The TPM manufacturers accepted in an AIK certificate's Subject Alternative Name: the product implementations
    /// in the TCG TPM Vendor ID Registry, in upper-case hex.
    /// </summary>
    public static readonly HashSet<string> TPMManufacturers =
    [
        // TCG TPM Vendor ID Registry, Family 1.2 and 2.0, Version 1.06 Revision 0.96 (2024-08-30), section 4.1 Product Implementations
        // https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.06-Revision-0.96_pub.pdf
        ConvertTPMManufacturerToHexString("id:414D4400"), // 'AMD' AMD
        ConvertTPMManufacturerToHexString("id:414E5400"), // 'ANT' Ant Group
        ConvertTPMManufacturerToHexString("id:41544D4C"), // 'ATML' Atmel
        ConvertTPMManufacturerToHexString("id:4252434D"), // 'BRCM' Broadcom
        ConvertTPMManufacturerToHexString("id:4353434F"), // 'CSCO' Cisco
        ConvertTPMManufacturerToHexString("id:464C5953"), // 'FLYS' Flyslice Technologies
        ConvertTPMManufacturerToHexString("id:48504900"), // 'HPI' HPI
        ConvertTPMManufacturerToHexString("id:48504500"), // 'HPE' HPE
        ConvertTPMManufacturerToHexString("id:48495349"), // 'HISI' Huawei
        ConvertTPMManufacturerToHexString("id:49424d00"), // 'IBM' IBM
        ConvertTPMManufacturerToHexString("id:49465800"), // 'IFX' Infinion
        ConvertTPMManufacturerToHexString("id:494E5443"), // 'INTC' Intel
        ConvertTPMManufacturerToHexString("id:4C454E00"), // 'LEN' Lenovo
        ConvertTPMManufacturerToHexString("id:4D534654"), // 'MSFT' Microsoft
        ConvertTPMManufacturerToHexString("id:4E534D20"), // 'NSM' National Semiconductor
        ConvertTPMManufacturerToHexString("id:4E545A00"), // 'NTZ' Nationz
        ConvertTPMManufacturerToHexString("id:4E534700"), // 'NSG' NSING
        ConvertTPMManufacturerToHexString("id:4E544300"), // 'NTC' Nuvoton Technology
        ConvertTPMManufacturerToHexString("id:51434F4D"), // 'QCOM' Qualcomm
        ConvertTPMManufacturerToHexString("id:534D5343"), // 'SMSC' SMSC
        ConvertTPMManufacturerToHexString("id:53544D20"), // 'STM ' ST Microelectronics
        ConvertTPMManufacturerToHexString("id:534D534E"), // 'SMSN' Samsung
        ConvertTPMManufacturerToHexString("id:53454345"), // 'SECE' SecEdge
        ConvertTPMManufacturerToHexString("id:534E5300"), // 'SNS' Sinosun
        ConvertTPMManufacturerToHexString("id:54584E00"), // 'TXN' Texas Instruments
        ConvertTPMManufacturerToHexString("id:57454300"), // 'WEC' Winbond
        ConvertTPMManufacturerToHexString("id:524F4343"), // 'ROCC' Fuzhou Rockchip
        ConvertTPMManufacturerToHexString("id:474F4F47"), // 'GOOG' Google
    ];

    public override ValueTask<VerifyAttestationResult> VerifyAsync(VerifyAttestationRequest request)
    {
        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // (handled in base class)
        if (!request.TryGetSig(out byte[]? sig))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidTpmAttestationSignature);

        if (!(request.TryGetVer(out var ver) && ver is "2.0"))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "FIDO2 only supports TPM 2.0");

        // 2. Verify that the public key specified by the parameters and unique fields of pubArea
        // is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData
        PubArea? pubArea = null;
        if (request.AttStmt["pubArea"] is CborByteString { Length: > 0 } pubAreaObject)
        {
            pubArea = ParseTpmStructure(pubAreaObject.Value, static bytes => new PubArea(bytes), "Missing or malformed pubArea");
        }

        if (pubArea is null || pubArea.Unique is null || pubArea.Unique.Length is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Missing or malformed pubArea");

        // The credential public key comes from the client-supplied authenticator data, while certInfo (below) only
        // certifies the key described by pubArea. The two must therefore be the same key, for every key type the
        // credential public key can take: a TPM 2.0 key is either RSA or ECC, so any other kind of credential
        // public key cannot be the one pubArea describes and the attestation is rejected outright.
        var credentialPublicKey = request.AuthData.AttestedCredentialData!.CredentialPublicKey;
        switch (credentialPublicKey._type)
        {
            case COSE.KeyType.RSA:
                {
                    if (pubArea.TypeAlg is not TpmAlg.TPM_ALG_RSA)
                        throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"pubArea type {pubArea.TypeAlg} does not match RSA credentialPublicKey");

                    ReadOnlySpan<byte> coseMod = (byte[])request.CredentialPublicKey[COSE.KeyTypeParameter.N]; // modulus
                    ReadOnlySpan<byte> coseExp = (byte[])request.CredentialPublicKey[COSE.KeyTypeParameter.E]; // exponent

                    if (!coseMod.SequenceEqual(pubArea.Unique))
                        throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Public key mismatch between pubArea and credentialPublicKey");

                    // COSE encodes e as an unsigned big-endian integer of whatever length it needs (RFC 8230 section 4);
                    // pubArea carries it as a fixed 32-bit field, so anything that doesn't fit cannot be the same exponent.
                    if (!TryReadUInt32BigEndian(coseExp, out uint coseExponent) || coseExponent != pubArea.Exponent)
                        throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Public key exponent mismatch between pubArea and credentialPublicKey");

                    break;
                }
            case COSE.KeyType.EC2:
                {
                    if (pubArea.TypeAlg is not TpmAlg.TPM_ALG_ECC)
                        throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"pubArea type {pubArea.TypeAlg} does not match EC2 credentialPublicKey");

                    var curve = (int)request.CredentialPublicKey[COSE.KeyTypeParameter.Crv];
                    var x = (byte[])request.CredentialPublicKey[COSE.KeyTypeParameter.X];
                    var y = (byte[])request.CredentialPublicKey[COSE.KeyTypeParameter.Y];

                    if (!CoseCurveToTpm.TryGetValue(curve, out var expectedTpmCurve))
                        throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"Curve {(COSE.EllipticCurve)curve} of credentialPublicKey is not supported by TPM attestation");

                    if (pubArea.EccCurve != expectedTpmCurve)
                        throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Curve mismatch between pubArea and credentialPublicKey");

                    if (!pubArea.ECPoint.X.AsSpan().SequenceEqual(x))
                        throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "X-coordinate mismatch between pubArea and credentialPublicKey");

                    if (!pubArea.ECPoint.Y.AsSpan().SequenceEqual(y))
                        throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Y-coordinate mismatch between pubArea and credentialPublicKey");

                    break;
                }
            default:
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"TPM attestation requires an RSA or EC2 credential public key, got {credentialPublicKey._type}");
        }

        // 3. Concatenate authenticatorData and clientDataHash to form attToBeSigned
        // See Data field of base class

        // 4. Validate that certInfo is valid
        var certInfo = request.AttStmt["certInfo"] is CborByteString { Length: > 0 } certInfoObject
            ? ParseTpmStructure(certInfoObject.Value, static bytes => new CertInfo(bytes), "CertInfo invalid parsing TPM format attStmt")
            : throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "CertInfo invalid parsing TPM format attStmt");

        // 4a. Verify that magic is set to TPM_GENERATED_VALUE
        // Handled in CertInfo constructor, see CertInfo.Magic

        // 4b. Verify that type is set to TPM_ST_ATTEST_CERTIFY
        // Handled in CertInfo constructor, see CertInfo.Type

        // 4c. Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg"
        if (!request.TryGetAlg(out var alg))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidTpmAttestationAlgorithm);

        ReadOnlySpan<byte> dataHash = CryptoUtils.HashData(CryptoUtils.HashAlgFromCOSEAlg(alg), request.Data);

        if (!dataHash.SequenceEqual(certInfo.ExtraData))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Hash value mismatch extraData and attToBeSigned");

        // 4d. Verify that attested contains a TPMS_CERTIFY_INFO structure, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea
        ReadOnlySpan<byte> pubAreaRawHash = CryptoUtils.HashData(CryptoUtils.HashAlgFromCOSEAlg((COSE.Algorithm)certInfo.Alg), pubArea.Raw);

        if (!pubAreaRawHash.SequenceEqual(certInfo.AttestedName))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Hash value mismatch attested and pubArea");

        // 4e. Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an input to risk engines.

        // 5. If x5c is present, this indicates that the attestation type is not ECDAA
        if (request.X5c is CborArray { Length: > 0 } x5cArray)
        {
            var trustPath = new X509Certificate2[x5cArray.Length];

            for (int i = 0; i < x5cArray.Length; i++)
            {
                if (x5cArray[i] is CborByteString { Length: > 0 } x5cObject)
                {
                    trustPath[i] = X509CertificateHelper.CreateFromRawData(x5cObject.Value);
                }
                else
                {
                    throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MalformedX5c_TpmAttestation);
                }
            }

            // 5a. Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
            X509Certificate2 aikCert = trustPath[0];

            var cpk = new CredentialPublicKey(aikCert, alg);

            if (!cpk.Verify(certInfo.Raw, sig))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Bad signature in TPM with aikCert");

            // 5b. Verify that aikCert meets the TPM attestation statement certificate requirements
            // https://www.w3.org/TR/webauthn/#tpm-cert-requirements
            // 5bi. Version MUST be set to 3
            if (aikCert.Version != 3)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "aikCert must be V3");

            // 5bii. Subject field MUST be set to empty - they actually mean subject name
            if (aikCert.SubjectName.Name.Length != 0)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "aikCert subject must be empty");

            // 5biii. The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
            // https://www.w3.org/TR/webauthn/#tpm-cert-requirements
            (string? tpmManufacturer, string? tpmModel, string? tpmVersion) = SANFromAttnCertExts(aikCert.Extensions);

            // From https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
            // "The issuer MUST include TPM manufacturer, TPM part number and TPM firmware version, using the directoryName
            // form within the GeneralName structure. The ASN.1 encoding is specified in section 3.1.2 TPM Device
            // Attributes. In accordance with RFC 5280[11], this extension MUST be critical if subject is empty
            // and SHOULD be non-critical if subject is non-empty"

            // Best I can figure to do for now?
            if (string.IsNullOrEmpty(tpmManufacturer) ||
                string.IsNullOrEmpty(tpmModel) ||
                string.IsNullOrEmpty(tpmVersion))
            {
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate");
            }

            if (TryConvertTPMManufacturerToHexString(tpmManufacturer) is not string manufacturerId || !IsAcceptedManufacturer(manufacturerId, request.ValidationMode))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Invalid TPM manufacturer found parsing TPM attestation");

            // 5biiii. The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
            // OID is 2.23.133.8.3
            bool eku = EKUFromAttnCertExts(aikCert.Extensions, "2.23.133.8.3");

            if (!eku)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "aikCert EKU missing tcg-kp-AIKCertificate OID");

            // 5biiiii. The Basic Constraints extension MUST have the CA component set to false.
            if (IsAttnCertCACert(aikCert.Extensions))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "aikCert Basic Constraints extension CA component must be false");

            // 5biiiiii. An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280]
            // are both OPTIONAL as the status of many attestation certificates is available through metadata services.
            // See, for example, the FIDO Metadata Service [FIDOMetadataService].

            // 5c. If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData
            if (AaguidFromAttnCertExts(aikCert.Extensions) is byte[] aaguid &&
                (!aaguid.AsSpan().SequenceEqual(Guid.Empty.ToByteArray())) &&
                (new Guid(aaguid, bigEndian: true).CompareTo(request.AuthData.AttestedCredentialData!.AaGuid) != 0))
            {
                throw new Fido2VerificationException($"aaguid malformed, expected {request.AuthData.AttestedCredentialData.AaGuid}, got {new Guid(aaguid, bigEndian: true)}");
            }

            return new(new VerifyAttestationResult(AttestationType.AttCa, trustPath));
        }
        // If ecdaaKeyId is present, then the attestation type is ECDAA
        else if (request.EcdaaKeyId != null)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.UnimplementedAlgorithm, Fido2ErrorMessages.UnimplementedAlgorithm_Ecdaa_Tpm);

            // Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo
            // https://www.w3.org/TR/webauthn/#biblio-fidoecdaaalgorithm

            // If successful, return attestation type ECDAA and the identifier of the ECDAA-Issuer public key ecdaaKeyId.
            // attnType = AttestationType.ECDAA;
            // trustPath = ecdaaKeyId;
        }
        else
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Neither x5c nor ECDAA were found in the TPM attestation statement");
        }
    }

    private static readonly Dictionary<int, TpmEccCurve> CoseCurveToTpm = new()
    {
        { 1, TpmEccCurve.TPM_ECC_NIST_P256},
        { 2, TpmEccCurve.TPM_ECC_NIST_P384},
        { 3, TpmEccCurve.TPM_ECC_NIST_P521}
    };

    private static bool IsAcceptedManufacturer(string manufacturerId, FidoValidationMode validationMode)
    {
        if (TPMManufacturers.Contains(manufacturerId))
            return true;

        return validationMode is FidoValidationMode.FidoConformance2024 && manufacturerId == FidoConformanceToolTpmManufacturer;
    }

    /// <summary>
    /// Runs one of the TPM structure parsers over attacker-supplied bytes. The parsers index into fixed-size
    /// fields, so a truncated or otherwise malformed structure would surface as an ArgumentOutOfRangeException
    /// or the like; anything that is not already a <see cref="Fido2VerificationException"/> is reported as one.
    /// </summary>
    private static T ParseTpmStructure<T>(byte[] bytes, Func<byte[], T> parse, string message)
    {
        try
        {
            return parse(bytes);
        }
        catch (Fido2VerificationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, message, ex);
        }
    }

    /// <summary>
    /// Reads an unsigned big-endian integer of any length, as COSE encodes an RSA public exponent, provided its
    /// value fits in 32 bits (leading zero octets are permitted).
    /// </summary>
    private static bool TryReadUInt32BigEndian(ReadOnlySpan<byte> bytes, out uint value)
    {
        value = 0;

        if (bytes.Length is 0)
            return false;

        bytes = bytes.TrimStart((byte)0);

        if (bytes.Length > sizeof(uint))
            return false;

        foreach (byte b in bytes)
        {
            value = (value << 8) | b;
        }

        return true;
    }

    private static (string?, string?, string?) SANFromAttnCertExts(X509ExtensionCollection exts)
    {
        string? tpmManufacturer = null;
        string? tpmModel = null;
        string? tpmVersion = null;

        var foundSAN = false;

        foreach (var extension in exts)
        {
            if (extension.Oid?.Value is "2.5.29.17") // subject alternative name
            {
                if (extension.RawData.Length is 0)
                    throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "SAN missing from TPM attestation certificate");

                foundSAN = true;

                var subjectAlternativeName = Asn1Element.Decode(extension.RawData);
                subjectAlternativeName.CheckTag(new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true));
                subjectAlternativeName.CheckMinimumSequenceLength(1);

                if (subjectAlternativeName.Sequence.FirstOrDefault(o => o is { TagClass: TagClass.ContextSpecific, TagValue: 4 /*Octet-String */ }) is Asn1Element generalName)
                {
                    generalName.CheckConstructed();
                    generalName.CheckExactSequenceLength(1);

                    var nameSequence = generalName[0];
                    nameSequence.CheckTag(new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true));
                    nameSequence.CheckMinimumSequenceLength(1);

                    /*

                    Per Trusted Computing Group Endorsement Key Credential Profile section 3.2.9:

                    "The issuer MUST include TPM manufacturer, TPM part number and TPM firmware version, using the directoryName-form within the GeneralName structure. The ASN.1 encoding is specified in section 3.1.2 TPM Device Attributes."

                    An example is provided in document section A.1 Example 1:

                                // SEQUENCE
                                30 49
                                     // SET
                                     31 16
                                         // SEQUENCE
                                         30 14
                                             // OBJECT IDENTIFER tcg-at-tpmManufacturer (2.23.133.2.1)
                                             06 05 67 81 05 02 01
                                             // UTF8 STRING id:54434700 (TCG)
                                             0C 0B 69 64 3A 35 34 34 33 34 37 30 30
                                    // SET
                                    31 17
                                        // SEQUENCE
                                        30 15
                                            // OBJECT IDENTIFER tcg-at-tpmModel (2.23.133.2.2)
                                            06 05 67 81 05 02 02
                                            // UTF8 STRING ABCDEF123456
                                            0C 0C 41 42 43 44 45 46 31 32 33 34 35 36
                                    // SET
                                    31 16
                                        // SEQUENCE
                                        30 14
                                            // OBJECT IDENTIFER tcg-at-tpmVersion (2.23.133.2.3)
                                            06 05 67 81 05 02 03
                                            // UTF8 STRING id:00010023
                                            0C 0B 69 64 3A 30 30 30 31 30 30 32 33

                    Some TPM implementations place each device attributes SEQUENCE within a single SET instead of each in its own SET.

                    This detects this condition and repacks each devices attributes SEQUENCE into its own SET to conform with TCG spec.

                     */

                    var deviceAttributes = nameSequence.Sequence;

                    if (deviceAttributes[0].Sequence.Count != 1)
                    {
                        var wrappedElements = new List<Asn1Element>(deviceAttributes[0].Sequence.Count);

                        foreach (Asn1Element o in deviceAttributes[0].Sequence)
                        {
                            wrappedElements.Add(Asn1Element.CreateSetOf([
                                Asn1Element.CreateSequence((List<Asn1Element>)o.Sequence)
                            ]));
                        }

                        deviceAttributes = wrappedElements;
                    }

                    foreach (Asn1Element propertySet in deviceAttributes)
                    {
                        propertySet.CheckTag(Asn1Tag.SetOf);
                        propertySet.CheckExactSequenceLength(1);

                        var propertySequence = propertySet[0];
                        propertySequence.CheckTag(Asn1Tag.Sequence);
                        propertySequence.CheckExactSequenceLength(2);

                        var propertyOid = propertySequence[0];
                        propertyOid.CheckTag(Asn1Tag.ObjectIdentifier);

                        var propertyValue = propertySequence[1];
                        propertyValue.CheckTag(new Asn1Tag(UniversalTagNumber.UTF8String));

                        switch (propertyOid.GetOID())
                        {
                            case "2.23.133.2.1":
                                tpmManufacturer = propertyValue.GetString();
                                break;
                            case "2.23.133.2.2":
                                tpmModel = propertyValue.GetString();
                                break;
                            case "2.23.133.2.3":
                                tpmVersion = propertyValue.GetString();
                                break;
                            default:
                                continue;
                        }
                    }
                }

                break;
            }
        }

        if (!foundSAN)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "SAN missing from TPM attestation certificate");

        return (tpmManufacturer, tpmModel, tpmVersion);
    }

    private static bool EKUFromAttnCertExts(X509ExtensionCollection exts, string expectedEnhancedKeyUsages)
    {
        foreach (var ext in exts)
        {
            if (ext.Oid?.Value is "2.5.29.37" && ext is X509EnhancedKeyUsageExtension enhancedKeyUsageExtension)
            {
                foreach (var oid in enhancedKeyUsageExtension.EnhancedKeyUsages)
                {
                    if (expectedEnhancedKeyUsages.Equals(oid.Value, StringComparison.Ordinal))
                        return true;
                }

            }
        }
        return false;
    }
}

public enum TpmEccCurve : ushort
{
    // TCG TPM Rev 2.0, part 2, structures, section 6.4, TPM_ECC_CURVE
    TPM_ECC_NONE,       // 0x0000
    TPM_ECC_NIST_P192,  // 0x0001
    TPM_ECC_NIST_P224,  // 0x0002
    TPM_ECC_NIST_P256,  // 0x0003
    TPM_ECC_NIST_P384,  // 0x0004
    TPM_ECC_NIST_P521,  // 0x0005
    TPM_ECC_BN_P256,    // 0x0010 curve to support ECDAA
    TPM_ECC_BN_P638,    // 0x0011 curve to support ECDAA
    TPM_ECC_SM2_P256    // 0x0020
}

public enum TpmAlg : ushort
{
    // TCG TPM Rev 2.0, part 2, structures, section 6.3, TPM_ALG_ID
    TPM_ALG_ERROR, // 0
    TPM_ALG_RSA, // 1
    TPM_ALG_SHA1 = 4, // 4
    TPM_ALG_HMAC, // 5
    TPM_ALG_AES, // 6
    TPM_ALG_MGF1, // 7
    TPM_ALG_KEYEDHASH, // 8
    TPM_ALG_XOR = 0xA, // A
    TPM_ALG_SHA256, // B
    TPM_ALG_SHA384, // C
    TPM_ALG_SHA512, // D
    TPM_ALG_NULL = 0x10, // 10
    TPM_ALG_SM3_256 = 0x12, // 12
    TPM_ALG_SM4, // 13
    TPM_ALG_RSASSA, // 14
    TPM_ALG_RSAES, // 15
    TPM_ALG_RSAPSS, // 16
    TPM_ALG_OAEP, // 17
    TPM_ALG_ECDSA, // 18
    TPM_ALG_ECDH, // 19
    TPM_ALG_ECDAA, // 1A
    TPM_ALG_SM2, // 1B
    TPM_ALG_ECSCHNORR, // 1C
    TPM_ALG_ECMQV, // 1D
    TPM_ALG_KDF1_SP800_56A = 0x20,
    TPM_ALG_KDF2, // 21
    TPM_ALG_KDF1_SP800_108, // 22
    TPM_ALG_ECC, // 23
    TPM_ALG_SYMCIPHER = 0x25,
    TPM_ALG_CAMELLIA, // 26
    TPM_ALG_CTR = 0x40,
    TPM_ALG_OFB, // 41
    TPM_ALG_CBC, // 42
    TPM_ALG_CFB, // 43
    TPM_ALG_ECB // 44
};

// TPMS_ATTEST, TPMv2-Part2, section 10.12.8
public sealed class CertInfo
{
    private readonly byte[] _data;

    public CertInfo(byte[] data)
    {
        if (data is null || data.Length is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Malformed certInfo bytes");

        int offset = 0;

        _data = data;

        Magic = AuthDataHelper.GetSizedByteArray(data, ref offset, 4);
        if (0xff544347 != BinaryPrimitives.ReadUInt32BigEndian(Magic))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Bad magic number " + Convert.ToHexString(Magic));

        Type = AuthDataHelper.GetSizedByteArray(data, ref offset, 2);
        if (0x8017 != BinaryPrimitives.ReadUInt16BigEndian(Type))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Bad structure tag " + Convert.ToHexString(Type));

        QualifiedSigner = AuthDataHelper.GetSizedByteArray(data, ref offset);

        ExtraData = AuthDataHelper.GetSizedByteArray(data, ref offset);
        if (ExtraData is null || ExtraData.Length is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Bad extraData in certInfo");

        Clock = AuthDataHelper.GetSizedByteArray(data, ref offset, 8);
        ResetCount = AuthDataHelper.GetSizedByteArray(data, ref offset, 4);
        RestartCount = AuthDataHelper.GetSizedByteArray(data, ref offset, 4);
        Safe = AuthDataHelper.GetSizedByteArray(data, ref offset, 1);
        FirmwareVersion = AuthDataHelper.GetSizedByteArray(data, ref offset, 8);

        var (size, name) = NameFromTPM2BName(data, ref offset);
        Alg = size; // TPM_ALG_ID
        AttestedName = name;
        AttestedQualifiedNameBuffer = AuthDataHelper.GetSizedByteArray(data, ref offset);

        if (data.Length != offset)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Leftover bits decoding certInfo");
    }
    public ReadOnlySpan<byte> Raw => _data;

    public byte[] Magic { get; }
    public byte[] Type { get; }
    public byte[] QualifiedSigner { get; }
    public byte[] ExtraData { get; }
    public byte[] Clock { get; }
    public byte[] ResetCount { get; }
    public byte[] RestartCount { get; }
    public byte[] Safe { get; }
    public byte[] FirmwareVersion { get; }
    public ushort Alg { get; }
    public byte[] AttestedName { get; }
    public byte[] AttestedQualifiedNameBuffer { get; }

    private static readonly Dictionary<TpmAlg, ushort> s_tpmAlgToDigestSizeMap = new()
    {
        { TpmAlg.TPM_ALG_SHA1,   SHA1.HashSizeInBytes },
        { TpmAlg.TPM_ALG_SHA256, SHA256.HashSizeInBytes },
        { TpmAlg.TPM_ALG_SHA384, SHA384.HashSizeInBytes },
        { TpmAlg.TPM_ALG_SHA512, SHA512.HashSizeInBytes }
    };

    public static (ushort size, byte[] name) NameFromTPM2BName(ReadOnlySpan<byte> ab, ref int offset)
    {
        // TCG TPM Rev 2.0, part 2, structures, section 10.5.3, TPM2B_NAME
        // This buffer holds a Name for any entity type.
        // The type of Name in the structure is determined by context and the size parameter.
        ushort totalSize = 0;
        if (AuthDataHelper.GetSizedByteArray(ab, ref offset, 2) is byte[] totalBytes)
        {
            totalSize = BinaryPrimitives.ReadUInt16BigEndian(totalBytes);
        }

        ushort size = 0;
        var bytes = AuthDataHelper.GetSizedByteArray(ab, ref offset, 2);
        if (bytes != null)
        {
            size = BinaryPrimitives.ReadUInt16BigEndian(bytes);
        }

        // If size is 4, then the Name is a handle.
        if (size is 4)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Unexpected handle in TPM2B_NAME");

        // If size is 0, then no Name is present.
        if (size is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Unexpected no name found in TPM2B_NAME");

        // Otherwise, the size shall be the size of a TPM_ALG_ID plus the size of the digest produced by the indicated hash algorithm.
        byte[] name;
        if (Enum.IsDefined(typeof(TpmAlg), size))
        {
            var tpmalg = (TpmAlg)size;
            if (s_tpmAlgToDigestSizeMap.TryGetValue(tpmalg, out ushort tplAlgDigestSize))
            {
                name = AuthDataHelper.GetSizedByteArray(ab, ref offset, tplAlgDigestSize);
            }
            else
            {
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "TPM_ALG_ID found in TPM2B_NAME not acceptable hash algorithm");
            }
        }
        else
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Invalid TPM_ALG_ID found in TPM2B_NAME");
        }

        if (totalSize != bytes!.Length + name.Length)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Unexpected extra bytes found in TPM2B_NAME");

        return (size, name);
    }
}

// TPMT_PUBLIC, TPMv2-Part2, section 12.2.4
public sealed class PubArea
{
    private readonly byte[] _data;

    public PubArea(byte[] data)
    {
        _data = data;
        var offset = 0;

        // TPMI_ALG_PUBLIC
        Type = AuthDataHelper.GetSizedByteArray(data, ref offset, 2);
        var tpmAlg = (TpmAlg)Enum.ToObject(typeof(TpmAlg), BinaryPrimitives.ReadUInt16BigEndian(Type));

        // TPMI_ALG_HASH
        Alg = AuthDataHelper.GetSizedByteArray(data, ref offset, 2);

        // TPMA_OBJECT, attributes that, along with type, determine the manipulations of this object
        Attributes = AuthDataHelper.GetSizedByteArray(data, ref offset, 4);

        // TPM2B_DIGEST, optional policy for using this key, computed using the alg of the object
        Policy = AuthDataHelper.GetSizedByteArray(data, ref offset);

        // TPMU_PUBLIC_PARMS
        Symmetric = null;
        Scheme = null;

        if (tpmAlg is TpmAlg.TPM_ALG_KEYEDHASH)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.UnimplementedAlgorithm, "TPM_ALG_KEYEDHASH not yet supported");
        }
        if (tpmAlg is TpmAlg.TPM_ALG_SYMCIPHER)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.UnimplementedAlgorithm, "TPM_ALG_SYMCIPHER not yet supported");
        }

        // TPMS_ASYM_PARMS, for TPM_ALG_RSA and TPM_ALG_ECC
        if (tpmAlg is TpmAlg.TPM_ALG_RSA or TpmAlg.TPM_ALG_ECC)
        {
            Symmetric = AuthDataHelper.GetSizedByteArray(data, ref offset, 2);
            Scheme = AuthDataHelper.GetSizedByteArray(data, ref offset, 2);

            // TPMU_ASYM_SCHEME (via TPMT_RSA_SCHEME/TPMT_ECC_SCHEME): unless scheme is TPM_ALG_NULL, the
            // selector above is followed by scheme-specific detail. Every scheme this library can encounter
            // here (RSASSA, RSAPSS, OAEP, ECDSA, ECDH, ECSCHNORR, SM2) carries a single TPMI_ALG_HASH; ECDAA
            // additionally carries a UINT16 count. Both are fixed-size, so skipping them (rather than
            // interpreting them) is enough to keep the offset aligned for CurveID/KDF/Unique below.
            var schemeAlg = (TpmAlg)Enum.ToObject(typeof(TpmAlg), BinaryPrimitives.ReadUInt16BigEndian(Scheme));
            if (schemeAlg is not TpmAlg.TPM_ALG_NULL)
            {
                _ = AuthDataHelper.GetSizedByteArray(data, ref offset, 2); // hashAlg

                if (schemeAlg is TpmAlg.TPM_ALG_ECDAA)
                    _ = AuthDataHelper.GetSizedByteArray(data, ref offset, 2); // count
            }
        }

        // TPMI_RSA_KEY_BITS, number of bits in the public modulus
        KeyBits = null;

        // The public exponent, a prime number greater than 2.
        Exponent = 0;

        if (tpmAlg is TpmAlg.TPM_ALG_RSA)
        {
            KeyBits = AuthDataHelper.GetSizedByteArray(data, ref offset, 2);

            if (AuthDataHelper.GetSizedByteArray(data, ref offset, 4) is byte[] tmp)
            {
                // TPM canonical form puts the least significant octet of a multi-octet value last, i.e. big-endian
                // (TPMv2-Part1, 4.13 "canonical form", and the KDFa definition in 11.4.9.1: "the least significant
                // bits of the value in the highest numbered octet")
                Exponent = BinaryPrimitives.ReadUInt32BigEndian(tmp);

                // When zero, indicates that the exponent is the default of 2^16 + 1
                if (Exponent is 0)
                {
                    Exponent = Convert.ToUInt32(Math.Pow(2, 16) + 1);
                }
            }
            // TPM2B_PUBLIC_KEY_RSA
            Unique = AuthDataHelper.GetSizedByteArray(data, ref offset);
        }

        // TPMI_ECC_CURVE
        CurveID = null;

        // TPMT_KDF_SCHEME, an optional key derivation scheme for generating a symmetric key from a Z value
        // If the kdf  parameter associated with curveID is not TPM_ALG_NULL then this is required to be NULL.
        // NOTE There are currently no commands where this parameter has effect and, in the reference code, this field needs to be set to TPM_ALG_NULL.
        KDF = null;

        if (tpmAlg is TpmAlg.TPM_ALG_ECC)
        {
            CurveID = AuthDataHelper.GetSizedByteArray(data, ref offset, 2);
            KDF = AuthDataHelper.GetSizedByteArray(data, ref offset, 2);

            // TPMS_ECC_POINT
            ECPoint = new()
            {
                X = AuthDataHelper.GetSizedByteArray(data, ref offset),
                Y = AuthDataHelper.GetSizedByteArray(data, ref offset),
            };
            Unique = [.. ECPoint.X, .. ECPoint.Y];
        }

        if (data.Length != offset)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Leftover bytes decoding pubArea");
    }

    public ReadOnlySpan<byte> Raw => _data;

    public byte[] Type { get; }

    /// <summary>
    /// The TPMI_ALG_PUBLIC field (<see cref="Type"/>) as a <see cref="TpmAlg"/>.
    /// </summary>
    internal TpmAlg TypeAlg => (TpmAlg)BinaryPrimitives.ReadUInt16BigEndian(Type);

    public byte[] Alg { get; }
    public byte[] Attributes { get; }
    public byte[] Policy { get; }
    public byte[]? Symmetric { get; }
    public byte[]? Scheme { get; }
    public byte[]? KeyBits { get; }
    public uint Exponent { get; }
    public byte[]? CurveID { get; }
    public byte[]? KDF { get; }
    public byte[]? Unique { get; }
    public TpmEccCurve EccCurve => (TpmEccCurve)Enum.ToObject(typeof(TpmEccCurve), BinaryPrimitives.ReadUInt16BigEndian(CurveID));
    public ECPoint ECPoint { get; }
}
