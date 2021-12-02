﻿using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    internal class Packed : AttestationVerifier
    {
        private static readonly string[] s_newLine = new string[] { Environment.NewLine };

        public static bool IsValidPackedAttnCertSubject(string attnCertSubj)
        {
            // parse the DN string using standard rules
            var dictSubjectObj = new X500DistinguishedName(attnCertSubj);

            // form the string for splitting using new lines to avoid issues with commas
            var dictSubjectString = dictSubjectObj.Decode(X500DistinguishedNameFlags.UseNewLines); 
            var dictSubject = dictSubjectString.Split(s_newLine, StringSplitOptions.None)
                                          .Select(part => part.Split('='))
                                          .ToDictionary(split => split[0], split => split[1]);

            return dictSubject["C"].Length != 0 
                && dictSubject["O"].Length != 0 
                && dictSubject["OU"].Length != 0 
                && dictSubject["CN"].Length != 0 
                && dictSubject["OU"].ToString() is "Authenticator Attestation";
        }

        public override (AttestationType, X509Certificate2[]?) Verify()
        {
            // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and 
            // perform CBOR decoding on it to extract the contained fields.
            if (attStmt.Count is 0)
                throw new Fido2VerificationException("Attestation format packed must have attestation statement");

            if (!(Sig is CborByteString { Length: > 0 }))
                throw new Fido2VerificationException("Invalid packed attestation signature");

            if (!(Alg is CborInteger))
                throw new Fido2VerificationException("Invalid packed attestation algorithm");

            var alg = (COSE.Algorithm)(int)Alg;

            // 2. If x5c is present, this indicates that the attestation type is not ECDAA
            if (X5c != null)
            {
                if (!(X5c is CborArray { Length: > 0 } x5cArray) || EcdaaKeyId != null)
                    throw new Fido2VerificationException("Malformed x5c array in packed attestation statement");

                var trustPath = new X509Certificate2[x5cArray.Length];

                for (int i = 0; i < trustPath.Length; i++)
                {
                    if (X5c[i] is CborByteString { Length: > 0 } x5cObject)
                    {
                        var x5cCert = new X509Certificate2(x5cObject.Value);

                        // X509Certificate2.NotBefore/.NotAfter return LOCAL DateTimes, so
                        // it's correct to compare using DateTime.Now.
                        if (DateTime.Now < x5cCert.NotBefore || DateTime.Now > x5cCert.NotAfter)
                            throw new Fido2VerificationException("Packed signing certificate expired or not yet valid");

                        trustPath[i] = x5cCert;
                    }
                    else
                    {
                        throw new Fido2VerificationException("Malformed x5c cert found in packed attestation statement");
                    }                   
                }

                // The attestation certificate attestnCert MUST be the first element in the array.
                X509Certificate2 attestnCert = trustPath[0];

                // 2a. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
                // using the attestation public key in attestnCert with the algorithm specified in alg
                var cpk = new CredentialPublicKey(attestnCert, alg);

                if (!cpk.Verify(Data, (byte[])Sig))
                    throw new Fido2VerificationException("Invalid full packed signature");

                // Verify that attestnCert meets the requirements in https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements
                // 2bi. Version MUST be set to 3
                if (attestnCert.Version != 3)
                    throw new Fido2VerificationException("Packed x5c attestation certificate not V3");

                // 2bii. Subject field MUST contain C, O, OU, CN
                // OU must match "Authenticator Attestation"
                if (!IsValidPackedAttnCertSubject(attestnCert.Subject))
                    throw new Fido2VerificationException("Invalid attestation cert subject");

                // 2biii. If the related attestation root certificate is used for multiple authenticator models, 
                // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING
                // verify that the value of this extension matches the aaguid in authenticatorData
                var aaguid = AaguidFromAttnCertExts(attestnCert.Extensions);

                // 2biiii. The Basic Constraints extension MUST have the CA component set to false
                if (IsAttnCertCACert(attestnCert.Extensions))
                    throw new Fido2VerificationException("Attestation certificate has CA cert flag present");

                // 2c. If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData
                if (aaguid != null)
                {
                    if (AttestedCredentialData.FromBigEndian(aaguid).CompareTo(AuthData.AttestedCredentialData.AaGuid) != 0)
                        throw new Fido2VerificationException("aaguid present in packed attestation cert exts but does not match aaguid from authData");
                }

                // id-fido-u2f-ce-transports 
                byte u2ftransports = U2FTransportsFromAttnCert(attestnCert.Extensions);

                // 2d. Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation
                
                return (AttestationType.AttCa, trustPath);
            }

            // 3. If ecdaaKeyId is present, then the attestation type is ECDAA
            else if (EcdaaKeyId != null)
            {
                throw new Fido2VerificationException("ECDAA is not yet implemented");

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
                if (!AuthData.AttestedCredentialData.CredentialPublicKey.IsSameAlg(alg))
                    throw new Fido2VerificationException("Algorithm mismatch between credential public key and authenticator data in self attestation statement");

                // 4b. Verify that sig is a valid signature over the concatenation of authenticatorData and 
                // clientDataHash using the credential public key with alg
                if (!AuthData.AttestedCredentialData.CredentialPublicKey.Verify(Data, (byte[])Sig))
                    throw new Fido2VerificationException("Failed to validate signature");

                return (AttestationType.Self, null);
            }
        }
    }
}
