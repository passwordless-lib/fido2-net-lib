using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

internal sealed class AndroidKey : AttestationVerifier
{
    public static byte[]? AttestationExtensionBytes(X509ExtensionCollection exts)
    {
        foreach (var ext in exts)
        {
            if (ext.Oid?.Value is "1.3.6.1.4.1.11129.2.1.17") // AttestationRecordOid
            {
                return ext.RawData;
            }
        }

        return null;
    }

    public static byte[] GetAttestationChallenge(byte[] attExtBytes)
    {
        // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
        // attestationChallenge at index 4

        var keyDescription = Asn1Element.Decode(attExtBytes);
        return keyDescription[4].GetOctetString();
    }

    public static bool FindAllApplicationsField(byte[] attExtBytes)
    {
        // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
        // check both software and tee enforced AuthorizationList objects for presence of "allApplications" tag, number 600

        var keyDescription = Asn1Element.Decode(attExtBytes);

        var softwareEnforced = keyDescription[6].Sequence;
        foreach (Asn1Element s in softwareEnforced)
        {
            if (s.TagValue is 600)
                return true;
        }

        var teeEnforced = keyDescription[7].Sequence;
        foreach (Asn1Element s in teeEnforced)
        {
            if (s.TagValue is 600)
                return true;
        }

        return false;
    }

    // Values and tag numbers from the Android KeyMint key attestation schema.
    // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
    private const int KM_TAG_PURPOSE = 1;
    private const int KM_TAG_ORIGIN = 702;
    private const int KM_ORIGIN_GENERATED = 0;
    private const int KM_PURPOSE_SIGN = 2;

    public static bool IsOriginGenerated(byte[] attExtBytes)
    {
        // The origin (tag 702) MUST be present in an authorization list and equal KM_ORIGIN_GENERATED.
        // An absent origin is not evidence the key was generated in secure hardware (it could have been
        // imported), so a missing tag must fail closed rather than default to "generated".
        var keyDescription = Asn1Element.Decode(attExtBytes);

        bool found = false;

        foreach (var authorizationList in new[] { keyDescription[6].Sequence, keyDescription[7].Sequence })
        {
            foreach (Asn1Element entry in authorizationList)
            {
                if (entry.TagValue is KM_TAG_ORIGIN)
                {
                    found = true;

                    if (entry[0].GetInt32() != KM_ORIGIN_GENERATED)
                        return false;
                }
            }
        }

        return found;
    }

    public static bool IsPurposeSign(byte[] attExtBytes)
    {
        // The purpose (tag 1) is a SET OF INTEGER. It MUST be present in an authorization list and contain
        // KM_PURPOSE_SIGN. An absent purpose must fail closed rather than default to "sign", and the whole
        // set is inspected rather than only its first element.
        var keyDescription = Asn1Element.Decode(attExtBytes);

        bool found = false;

        foreach (var authorizationList in new[] { keyDescription[6].Sequence, keyDescription[7].Sequence })
        {
            foreach (Asn1Element entry in authorizationList)
            {
                if (entry.TagValue is KM_TAG_PURPOSE)
                {
                    found = true;

                    bool containsSign = false;
                    foreach (Asn1Element purpose in entry[0].Sequence)
                    {
                        if (purpose.GetInt32() == KM_PURPOSE_SIGN)
                        {
                            containsSign = true;
                            break;
                        }
                    }

                    if (!containsSign)
                        return false;
                }
            }
        }

        return found;
    }

    public override ValueTask<VerifyAttestationResult> VerifyAsync(VerifyAttestationRequest request)
    {
        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields
        // (handled in base class)
        if (request.AttStmt.Count is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MissingAndroidKeyAttestationStatement);

        if (!request.TryGetSig(out byte[]? sig))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidAndroidKeyAttestationSignature);

        // 2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
        // using the attestation public key in attestnCert with the algorithm specified in alg
        if (!(request.X5c is CborArray { Length: > 0 } x5cArray))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation);

        if (!request.TryGetAlg(out var alg))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidAndroidKeyAttestationAlgorithm);

        var trustPath = new X509Certificate2[x5cArray.Length];

        for (int i = 0; i < x5cArray.Length; i++)
        {
            if (x5cArray[i] is CborByteString { Length: > 0 } x5cObject)
            {
                try
                {
                    trustPath[i] = X509CertificateHelper.CreateFromRawData(x5cObject.Value);
                }
                catch (Exception ex) when (i is 0)
                {
                    throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"Failed to extract public key from android key: {ex.Message}", ex);
                }
            }
            else
            {
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation);
            }
        }

        X509Certificate2 androidKeyCert = trustPath[0];

        // attestation public key; GetECDsaPublicKey returns null for any other key algorithm, and the
        // signature check below only handles ECDSA, so say so rather than dereference the null
        if (androidKeyCert.GetECDsaPublicKey() is not ECDsa androidKeyPubKey)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Android Key attestation certificate public key is not an Elliptic Curve (EC) public key");

        byte[] ecSignature;
        try
        {
            ecSignature = CryptoUtils.SigFromEcDsaSig(sig, androidKeyPubKey.KeySize);
        }
        catch (Exception ex)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Failed to decode android key attestation signature from ASN.1 encoded form", ex);
        }

        if (!androidKeyPubKey.VerifyData(request.Data, ecSignature, CryptoUtils.HashAlgFromCOSEAlg(alg)))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidAndroidKeyAttestationSignature);

        // 3. Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
        if (!request.AuthData.AttestedCredentialData!.CredentialPublicKey.Verify(request.Data, sig))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Incorrect credentialPublicKey in android key attestation");

        // 4. Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash
        var attExtBytes = AttestationExtensionBytes(androidKeyCert.Extensions);
        if (attExtBytes is null)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Android key attestation certificate contains no AttestationRecord extension");

        try
        {
            var attestationChallenge = GetAttestationChallenge(attExtBytes);
            if (!request.ClientDataHash.SequenceEqual(attestationChallenge))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Mismatch between attestationChallenge and hashedClientDataJson verifying android key attestation certificate extension");
        }
        catch (Exception)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Malformed android key AttestationRecord extension verifying android key attestation certificate extension");
        }

        // 5. Verify the following using the appropriate authorization list from the attestation certificate
        // extension data. A malformed authorization list must fail as a Fido2VerificationException rather than
        // escape as a raw ASN.1/index exception.
        try
        {
            // 5a. The AuthorizationList.allApplications field is not present, since PublicKeyCredential MUST be bound to the RP ID
            if (FindAllApplicationsField(attExtBytes))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Found all applications field in android key attestation certificate extension");

            // 5bi. The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED ( which == 0).
            if (!IsOriginGenerated(attExtBytes))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension");

            // 5bii. The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN (which == 2).
            if (!IsPurposeSign(attExtBytes))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension");
        }
        catch (Fido2VerificationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Malformed authorization list in android key attestation certificate extension", ex);
        }

        return new(new VerifyAttestationResult(AttestationType.Basic, trustPath));
    }
}
