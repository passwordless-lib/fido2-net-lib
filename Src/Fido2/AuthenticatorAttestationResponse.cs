#nullable disable

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib
{
    /// <summary>
    /// The AuthenticatorAttestationResponse interface represents the authenticator's response 
    /// to a client’s request for the creation of a new public key credential.
    /// It contains information about the new credential that can be used to identify it for later use, 
    /// and metadata that can be used by the Relying Party to assess the characteristics of the credential during registration.
    /// </summary>
    public class AuthenticatorAttestationResponse : AuthenticatorResponse
    {
        private AuthenticatorAttestationResponse(byte[] clientDataJson) : base(clientDataJson)
        {
        }

        public ParsedAttestationObject AttestationObject { get; set; }
        public AuthenticatorAttestationRawResponse Raw { get; private set; }

        public static AuthenticatorAttestationResponse Parse(AuthenticatorAttestationRawResponse rawResponse)
        {
            if (rawResponse is null || rawResponse.Response is null)
                throw new Fido2VerificationException("Expected rawResponse, got null");

            if (rawResponse.Response.AttestationObject is null || 0 == rawResponse.Response.AttestationObject.Length)
                throw new Fido2VerificationException("Missing AttestationObject");

            // 8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
            CBORObject cborAttestation;
            try
            {
                cborAttestation = CBORObject.DecodeFromBytes(rawResponse.Response.AttestationObject);
            }
            catch (CBORException ex)
            {
                throw new Fido2VerificationException("AttestationObject invalid CBOR", ex);
            }

            if (cborAttestation["fmt"] is null
                || CBORType.TextString != cborAttestation["fmt"].Type
                || cborAttestation["attStmt"] is null
                || CBORType.Map != cborAttestation["attStmt"].Type
                || cborAttestation["authData"] is null
                || CBORType.ByteString != cborAttestation["authData"].Type)
                throw new Fido2VerificationException("Malformed AttestationObject");

            var response = new AuthenticatorAttestationResponse(rawResponse.Response.ClientDataJson)
            {
                Raw = rawResponse,
                AttestationObject = new ParsedAttestationObject
                (
                    fmt      : cborAttestation["fmt"].AsString(),
                    attStmt  : cborAttestation["attStmt"], // convert to dictionary?
                    authData : cborAttestation["authData"].GetByteString()
                )
            };
            return response;
        }

        public async Task<AttestationVerificationSuccess> VerifyAsync(CredentialCreateOptions originalOptions, Fido2Configuration config, IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser, IMetadataService metadataService, byte[] requestTokenBindingId)
        {
            // https://www.w3.org/TR/webauthn/#registering-a-new-credential
            // 1. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
            // 2. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
            // Note: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.
            // Above handled in base class constructor

            // 3. Verify that the value of C.type is webauthn.create
            if (Type is not "webauthn.create")
                throw new Fido2VerificationException("AttestationResponse is not type webauthn.create");

            // 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.
            // 5. Verify that the value of C.origin matches the Relying Party's origin.
            // 6. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained. 
            // If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
            BaseVerify(config.Origin, originalOptions.Challenge, requestTokenBindingId);

            if (Raw.Id is null || Raw.Id.Length == 0)
                throw new Fido2VerificationException("AttestationResponse is missing Id");

            if (Raw.Type != PublicKeyCredentialType.PublicKey)
                throw new Fido2VerificationException("AttestationResponse is missing type with value 'public-key'");

            var authData = new AuthenticatorData(AttestationObject.AuthData);

            // 7. Compute the hash of response.clientDataJSON using SHA-256.
            byte[] clientDataHash, rpIdHash;
            using (var sha256 = SHA256.Create())
            {
                clientDataHash = sha256.ComputeHash(Raw.Response.ClientDataJson);
                rpIdHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(originalOptions.Rp.Id));
            }

            // 8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
            // Handled in AuthenticatorAttestationResponse::Parse()

            // 9. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party
            if (false == authData.RpIdHash.SequenceEqual(rpIdHash))
                throw new Fido2VerificationException("Hash mismatch RPID");

            // 10. Verify that the User Present bit of the flags in authData is set.
            if (false == authData.UserPresent)
                throw new Fido2VerificationException("User Present flag not set in authenticator data");

            // 11. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
            // see authData.UserVerified
            // TODO: Make this a configurable option and add check to require

            // 12. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, 
            // considering the client extension input values that were given as the extensions option in the create() call.  In particular, any extension identifier values 
            // in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., 
            // no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
            
            // TODO?: Implement sort of like this: ClientExtensions.Keys.Any(x => options.extensions.contains(x);

            if (false == authData.HasAttestedCredentialData)
                throw new Fido2VerificationException("Attestation flag not set on attestation data");

            // 13. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. 
            // An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA registry of the same name
            // https://www.w3.org/TR/webauthn/#defined-attestation-formats
            AttestationVerifier verifier = AttestationObject.Fmt switch
            {
                // TODO: Better way to build these mappings?
                "none" => new None(),                           // https://www.w3.org/TR/webauthn/#none-attestation
                "tpm" => new Tpm(),                             // https://www.w3.org/TR/webauthn/#tpm-attestation
                "android-key" => new AndroidKey(),              // https://www.w3.org/TR/webauthn/#android-key-attestation
                "android-safetynet" => new AndroidSafetyNet(),  // https://www.w3.org/TR/webauthn/#android-safetynet-attestation
                "fido-u2f" => new FidoU2f(),                    // https://www.w3.org/TR/webauthn/#fido-u2f-attestation
                "packed" => new Packed(),                       // https://www.w3.org/TR/webauthn/#packed-attestation
                "apple" => new Apple(),                       // https://www.w3.org/TR/webauthn/#apple-anonymous-attestation
                _ => throw new Fido2VerificationException("Missing or unknown attestation type"),
            };

            // 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, 
            // by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7
            (var attType, var trustPath) = verifier.Verify(AttestationObject.AttStmt, AttestationObject.AuthData, clientDataHash);

            // 15. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. 
            // For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
            var entry = metadataService?.GetEntry(authData.AttestedCredentialData.AaGuid);

            // while conformance testing, we must reject any authenticator that we cannot get metadata for
            if (metadataService?.ConformanceTesting() is true && entry is null && AttestationType.None != attType && AttestationObject.Fmt is not "fido-u2f")
                throw new Fido2VerificationException("AAGUID not found in MDS test metadata");

            if (null != trustPath)
            {
                // If the authenticator is listed as in the metadata as one that should produce a basic full attestation, build and verify the chain
                if ((entry?.MetadataStatement?.AttestationTypes.Contains(MetadataAttestationType.ATTESTATION_BASIC_FULL.ToEnumMemberValue()) ?? false) ||
                    (entry?.MetadataStatement?.AttestationTypes.Contains(MetadataAttestationType.ATTESTATION_PRIVACY_CA.ToEnumMemberValue()) ?? false))
                {
                    var attestationRootCertificates = entry.MetadataStatement.AttestationRootCertificates
                        .Select(x => new X509Certificate2(Convert.FromBase64String(x)))
                        .ToArray();

                    if (false == CryptoUtils.ValidateTrustChain(trustPath, attestationRootCertificates))
                    {
                        throw new Fido2VerificationException("Invalid certificate chain");
                    }
                }

                // If the authenticator is not listed as one that should produce a basic full attestation, the certificate should be self signed
                if ((!entry?.MetadataStatement?.AttestationTypes.Contains(MetadataAttestationType.ATTESTATION_BASIC_FULL.ToEnumMemberValue()) ?? false) &&
                    (!entry?.MetadataStatement?.AttestationTypes.Contains(MetadataAttestationType.ATTESTATION_PRIVACY_CA.ToEnumMemberValue()) ?? false) &&
                    (!entry?.MetadataStatement?.AttestationTypes.Contains(MetadataAttestationType.ATTESTATION_ANONCA.ToEnumMemberValue()) ?? false))
                {
                    if (trustPath.FirstOrDefault().Subject != trustPath.FirstOrDefault().Issuer)
                        throw new Fido2VerificationException("Attestation with full attestation from authenticator that does not support full attestation");
                }
            }

            // Check status resports for authenticator with undesirable status
            foreach (var report in entry?.StatusReports ?? Enumerable.Empty<StatusReport>())
            {
                if (true == Enum.IsDefined(typeof(UndesiredAuthenticatorStatus), (UndesiredAuthenticatorStatus)report.Status))
                    throw new Fido2VerificationException("Authenticator found with undesirable status");
            }

            // 16. Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows:
            // If self attestation was used, check if self attestation is acceptable under Relying Party policy.
            // If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of acceptable trust anchors obtained in step 15.
            // Otherwise, use the X.509 certificates returned by the verification procedure to verify that the attestation public key correctly chains up to an acceptable root certificate.

            // 17. Check that the credentialId is not yet registered to any other user. 
            // If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration
            if (false == await isCredentialIdUniqueToUser(new IsCredentialIdUniqueToUserParams(authData.AttestedCredentialData.CredentialID, originalOptions.User)))
            {
                throw new Fido2VerificationException("CredentialId is not unique to this user");
            }

            // 18. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), 
            // by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the Relying Party's system.
            var result = new AttestationVerificationSuccess()
            {
                CredentialId = authData.AttestedCredentialData.CredentialID,
                PublicKey = authData.AttestedCredentialData.CredentialPublicKey.GetBytes(),
                User = originalOptions.User,
                Counter = authData.SignCount,
                CredType = AttestationObject.Fmt,
                Aaguid = authData.AttestedCredentialData.AaGuid,
            };

            return result;
            // 19. If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.
            // This implementation throws if the outputs are not trustworthy for a particular attestation type.
        }

        /// <summary>
        /// The AttestationObject after CBOR parsing
        /// </summary>
        public sealed class ParsedAttestationObject
        {
            public ParsedAttestationObject(string fmt, CBORObject attStmt, byte[] authData)
            {
                Fmt = fmt;
                AttStmt = attStmt;
                AuthData = authData;
            }

            public string Fmt { get; set; }
            public CBORObject AttStmt { get; set; }
            public byte[] AuthData { get; set; }
        }
    }
}
