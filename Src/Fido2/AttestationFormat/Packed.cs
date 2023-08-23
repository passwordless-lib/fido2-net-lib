using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

internal sealed class Packed : AttestationVerifier
{
    public static bool IsValidPackedAttnCertSubject(string attnCertSubj)
    {
        // parse the DN string using standard rules
        var subjectObj = new X500DistinguishedName(attnCertSubj);

        // form the string for splitting using new lines to avoid issues with commas
        string subjectString = subjectObj.Decode(X500DistinguishedNameFlags.UseNewLines);

        var subjectMap = new Dictionary<string, string>(4);

        foreach (var line in subjectString.AsSpan().EnumerateLines())
        {
            int equalIndex = line.IndexOf('=');

            var lhs = line.Slice(0, equalIndex).ToString();
            var rhs = line.Slice(equalIndex + 1).ToString();

            subjectMap[lhs] = rhs;
        }

        return subjectMap.TryGetValue("C", out var c) && c.Length > 0
            && subjectMap.TryGetValue("O", out var o) && o.Length > 0
            && subjectMap.TryGetValue("OU", out var ou) && ou is "Authenticator Attestation"
            && subjectMap.TryGetValue("CN", out var cn) && cn.Length > 0;
    }

    public override (AttestationType, X509Certificate2[]) Verify(VerifyAttestationRequest request)
    {
        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and 
        // perform CBOR decoding on it to extract the contained fields.
        if (request.AttStmt.Count is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MissingPackedAttestationStatement);

        if (!request.TryGetSig(out byte[]? sig))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidPackedAttestationSignature);

        if (!request.TryGetAlg(out var alg))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidPackedAttestationAlgorithm);

        // 2. If x5c is present, this indicates that the attestation type is not ECDAA
        if (request.X5c is CborObject x5c)
        {
            if (!(x5c is CborArray { Length: > 0 } x5cArray) || request.EcdaaKeyId != null)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MalformedX5c_PackedAttestation);

            var trustPath = new X509Certificate2[x5cArray.Length];

            for (int i = 0; i < trustPath.Length; i++)
            {
                if (x5cArray[i] is CborByteString { Length: > 0 } x5cObject)
                {
                    var x5cCert = new X509Certificate2(x5cObject.Value);

                    // X509Certificate2.NotBefore/.NotAfter return LOCAL DateTimes, so
                    // it's correct to compare using DateTime.Now.
                    if (DateTime.Now < x5cCert.NotBefore || DateTime.Now > x5cCert.NotAfter)
                        throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Packed signing certificate expired or not yet valid");

                    trustPath[i] = x5cCert;
                }
                else
                {
                    throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Malformed x5c cert found in packed attestation statement");
                }
            }

            // The attestation certificate attestnCert MUST be the first element in the array.
            X509Certificate2 attestnCert = trustPath[0];

            // 2a. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
            // using the attestation public key in attestnCert with the algorithm specified in alg
            var cpk = new CredentialPublicKey(attestnCert, alg);

            if (!cpk.Verify(request.Data, sig))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Invalid full packed signature");

            // Verify that attestnCert meets the requirements in https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements
            // 2bi. Version MUST be set to 3
            if (attestnCert.Version != 3)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Packed x5c attestation certificate not V3");

            // 2bii. Subject field MUST contain C, O, OU, CN
            // OU must match "Authenticator Attestation"
            if (!IsValidPackedAttnCertSubject(attestnCert.Subject))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidAttestationCertSubject);

            // 2biii. If the related attestation root certificate is used for multiple authenticator models, 
            // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING
            // verify that the value of this extension matches the aaguid in authenticatorData
            var aaguid = AaguidFromAttnCertExts(attestnCert.Extensions);

            // 2biiii. The Basic Constraints extension MUST have the CA component set to false
            if (IsAttnCertCACert(attestnCert.Extensions))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Attestation certificate has CA cert flag present");

            // 2c. If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData
            if (aaguid != null)
            {
                if (GuidHelper.FromBigEndian(aaguid).CompareTo(request.AuthData.AttestedCredentialData!.AaGuid) != 0)
                    throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "aaguid present in packed attestation cert exts but does not match aaguid from authData");
            }

            // id-fido-u2f-ce-transports 
            byte u2fTransports = U2FTransportsFromAttnCert(attestnCert.Extensions);

            // 2d. Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation

            return (AttestationType.AttCa, trustPath);
        }

        // 3. If ecdaaKeyId is present, then the attestation type is ECDAA
        else if (request.EcdaaKeyId != null)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.UnimplementedAlgorithm, Fido2ErrorMessages.UnimplementedAlgorithm_Ecdaa_Packed);

            // 3a. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
            // using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId
            // https://www.w3.org/TR/webauthn/#biblio-fidoecdaaalgorithm

            // 3b. If successful, return attestation type ECDAA and attestation trust path ecdaaKeyId.
            // attnType = AttestationType.ECDAA;
            // trustPath = ecdaaKeyId;
        }
        // 4. If neither x5c nor ecdaaKeyId is present, self attestation is in use
        else
        {
            // 4a. Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData
            if (!request.AuthData.AttestedCredentialData!.CredentialPublicKey.IsSameAlg(alg))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Algorithm mismatch between credential public key and authenticator data in self attestation statement");

            // 4b. Verify that sig is a valid signature over the concatenation of authenticatorData and 
            // clientDataHash using the credential public key with alg
            if (!request.AuthData.AttestedCredentialData.CredentialPublicKey.Verify(request.Data, sig))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Failed to validate signature");

            return (AttestationType.Self, null!);
        }
    }
}
