using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib.AttestationFormat
{
    internal enum UndesiredAuthenticatorStatus
    {
        ATTESTATION_KEY_COMPROMISE = AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE,
        USER_VERIFICATION_BYPASS = AuthenticatorStatus.USER_VERIFICATION_BYPASS,
        USER_KEY_REMOTE_COMPROMISE = AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE,
        USER_KEY_PHYSICAL_COMPROMISE = AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE,
        REVOKED = AuthenticatorStatus.REVOKED
    };

    internal enum MetadataAttestationType
    {
        ATTESTATION_BASIC_FULL = 0x3e07,
        ATTESTATION_BASIC_SURROGATE = 0x3e08
    }

    internal class Packed : AttestationFormat
    {
        private readonly IMetadataService _metadataService;

        public Packed(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash, IMetadataService metadataService)
            : base(attStmt, authenticatorData, clientDataHash)
        {
            _metadataService = metadataService;
        }

        public static bool IsValidPackedAttnCertSubject(string attnCertSubj)
        {
            var dictSubject = attnCertSubj.Split(new string[] { ", " }, StringSplitOptions.None)
                                          .Select(part => part.Split('='))
                                          .ToDictionary(split => split[0], split => split[1]);
            return (0 != dictSubject["C"].Length ||
                0 != dictSubject["O"].Length ||
                0 != dictSubject["OU"].Length ||
                0 != dictSubject["CN"].Length ||
                "Authenticator Attestation" == dictSubject["OU"].ToString());
        }

        public override void Verify()
        {
            // Verify that attStmt is valid CBOR conforming to the syntax defined above and 
            // perform CBOR decoding on it to extract the contained fields.
            if (0 == attStmt.Keys.Count || 0 == attStmt.Values.Count)
                throw new Fido2VerificationException("Attestation format packed must have attestation statement");

            if (null == Sig || CBORType.ByteString != Sig.Type || 0 == Sig.GetByteString().Length)
                throw new Fido2VerificationException("Invalid packed attestation signature");

            if (null == Alg || CBORType.Number != Alg.Type)
                throw new Fido2VerificationException("Invalid packed attestation algorithm");

            // If x5c is present, this indicates that the attestation type is not ECDAA
            if (null != X5c)
            {
                if (CBORType.Array != X5c.Type || 0 == X5c.Count || null != EcdaaKeyId)
                    throw new Fido2VerificationException("Malformed x5c array in packed attestation statement");
                var enumerator = X5c.Values.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    if (null == enumerator || null == enumerator.Current
                        || CBORType.ByteString != enumerator.Current.Type
                        || 0 == enumerator.Current.GetByteString().Length)
                        throw new Fido2VerificationException("Malformed x5c cert found in packed attestation statement");

                    var x5ccert = new X509Certificate2(enumerator.Current.GetByteString());

                    if (DateTime.UtcNow < x5ccert.NotBefore || DateTime.UtcNow > x5ccert.NotAfter)
                        throw new Fido2VerificationException("Packed signing certificate expired or not yet valid");
                }

                // The attestation certificate attestnCert MUST be the first element in the array.
                var attestnCert = new X509Certificate2(X5c.Values.First().GetByteString());

                // 2a. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
                // using the attestation public key in attestnCert with the algorithm specified in alg
                var packedPubKey = attestnCert.GetECDsaPublicKey(); // attestation public key
                if (false == CryptoUtils.algMap.ContainsKey(Alg.AsInt32()))
                    throw new Fido2VerificationException("Invalid attestation algorithm");

                var cpk = new CredentialPublicKey(attestnCert, Alg.AsInt32());
                if (true != cpk.Verify(Data, Sig.GetByteString()))
                    throw new Fido2VerificationException("Invalid full packed signature");

                // Verify that attestnCert meets the requirements in https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements
                // 2b. Version MUST be set to 3
                if (3 != attestnCert.Version)
                    throw new Fido2VerificationException("Packed x5c attestation certificate not V3");

                // Subject field MUST contain C, O, OU, CN
                // OU must match "Authenticator Attestation"
                if (true != IsValidPackedAttnCertSubject(attestnCert.Subject))
                    throw new Fido2VerificationException("Invalid attestation cert subject");

                // 2c. If the related attestation root certificate is used for multiple authenticator models, 
                // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING
                // verify that the value of this extension matches the aaguid in authenticatorData
                var aaguid = AaguidFromAttnCertExts(attestnCert.Extensions);
                if (aaguid != null)
                {
                    if (0 != AttestedCredentialData.FromBigEndian(aaguid).CompareTo(AuthData.AttestedCredentialData.AaGuid))
                        throw new Fido2VerificationException("aaguid present in packed attestation but does not match aaguid from authData");
                }
                // 2d. The Basic Constraints extension MUST have the CA component set to false
                if (IsAttnCertCACert(attestnCert.Extensions))
                    throw new Fido2VerificationException("Attestion certificate has CA cert flag present");

                // id-fido-u2f-ce-transports 
                var u2ftransports = U2FTransportsFromAttnCert(attestnCert.Extensions);

                var trustPath = X5c.Values
                    .Select(x => new X509Certificate2(x.GetByteString()))
                    .ToArray();

                var entry = _metadataService?.GetEntry(AuthData.AttestedCredentialData.AaGuid);

                // while conformance testing, we must reject any authenticator that we cannot get metadata for
                if (_metadataService?.ConformanceTesting() == true && null == entry)
                    throw new Fido2VerificationException("AAGUID not found in MDS test metadata");

                // If the authenticator is listed as in the metadata as one that should produce a basic full attestation, build and verify the chain
                if (entry?.MetadataStatement?.AttestationTypes.Contains((ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL) ?? false)
                {
                    var root = new X509Certificate2(Convert.FromBase64String(entry.MetadataStatement.AttestationRootCertificates.FirstOrDefault()));
                    var chain = new X509Chain();
                    chain.ChainPolicy.ExtraStore.Add(root);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                    if (trustPath.Length > 1)
                    {
                        foreach (var cert in trustPath.Skip(1).Reverse())
                        {
                            chain.ChainPolicy.ExtraStore.Add(cert);
                        }
                    }
                    var valid = chain.Build(trustPath[0]);
                    if (false == valid)
                    {
                        throw new Fido2VerificationException("Invalid certificate chain in packed attestation");
                    }
                }

                // If the authenticator is not listed as one that should produce a basic full attestation, the certificate should be self signed
                if (!entry?.MetadataStatement?.AttestationTypes.Contains((ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL) ?? false)
                {
                    if (trustPath.FirstOrDefault().Subject != trustPath.FirstOrDefault().Issuer)
                        throw new Fido2VerificationException("Attestation with full attestation from authenticator that does not support full attestation");
                }

                // Check status resports for authenticator with undesirable status
                foreach (var report in entry?.StatusReports ?? Enumerable.Empty<StatusReport>())
                {
                    if (true == Enum.IsDefined(typeof(UndesiredAuthenticatorStatus), (UndesiredAuthenticatorStatus)report.Status))
                        throw new Fido2VerificationException("Authenticator found with undesirable status");
                }
            }

            // If ecdaaKeyId is present, then the attestation type is ECDAA
            else if (null != EcdaaKeyId)
            {
                // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
                // using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId
                // https://www.w3.org/TR/webauthn/#biblio-fidoecdaaalgorithm

                throw new Fido2VerificationException("ECDAA is not yet implemented");
                // If successful, return attestation type ECDAA and attestation trust path ecdaaKeyId.
                //attnType = AttestationType.ECDAA;
                //trustPath = ecdaaKeyId;
            }
            // If neither x5c nor ecdaaKeyId is present, self attestation is in use
            else
            {
                // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData
                if (false == AuthData.AttestedCredentialData.CredentialPublicKey.IsSameAlg((COSE.Algorithm)Alg.AsInt32()))
                    throw new Fido2VerificationException("Algorithm mismatch between credential public key and authenticator data in self attestation statement");

                // Verify that sig is a valid signature over the concatenation of authenticatorData and 
                // clientDataHash using the credential public key with alg

                if (true != AuthData.AttestedCredentialData.CredentialPublicKey.Verify(Data, Sig.GetByteString()))
                    throw new Fido2VerificationException("Failed to validate signature");
            }
        }
    }
}
