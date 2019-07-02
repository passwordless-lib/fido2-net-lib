using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib.Objects;
using Fido2NetLib.AttestationFormat;
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
            if (null == rawResponse || null == rawResponse.Response)
                throw new Fido2VerificationException("Expected rawResponse, got null");
            
            if (null == rawResponse.Response.AttestationObject || 0 == rawResponse.Response.AttestationObject.Length)
                throw new Fido2VerificationException("Missing AttestationObject");

            CBORObject cborAttestation = null;
            try
            {
                cborAttestation = CBORObject.DecodeFromBytes(rawResponse.Response.AttestationObject);
            }
            catch (CBORException)
            {
                throw new Fido2VerificationException("Malformed AttestationObject");
            }

            if (null == cborAttestation["fmt"] ||
                    CBORType.TextString != cborAttestation["fmt"].Type || 
                    null == cborAttestation["attStmt"] ||
                    CBORType.Map != cborAttestation["attStmt"].Type || 
                    null == cborAttestation["authData"] ||
                    CBORType.ByteString != cborAttestation["authData"].Type
                    ) throw new Fido2VerificationException("Malformed AttestationObject");

            var response = new AuthenticatorAttestationResponse(rawResponse.Response.ClientDataJson)
            {
                Raw = rawResponse,
                AttestationObject = new ParsedAttestationObject()
                {
                    Fmt = cborAttestation["fmt"].AsString(),
                    AttStmt = cborAttestation["attStmt"], // convert to dictionary?
                    AuthData = cborAttestation["authData"].GetByteString()
                }
            };
            return response;
        }

        public async Task<AttestationVerificationSuccess> VerifyAsync(CredentialCreateOptions originalOptions, Fido2NetLib.Fido2.Configuration config, IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser, IMetadataService metadataService, byte[] requestTokenBindingId)
        {
            BaseVerify(config.Origin, originalOptions.Challenge, requestTokenBindingId);
            // verify challenge is same as we expected
            // verify origin
            // done in baseclass

            if (Type != "webauthn.create")
                throw new Fido2VerificationException("AttestationResponse is not type webauthn.create");

            if (Raw.Id == null || Raw.Id.Length == 0)
                throw new Fido2VerificationException("AttestationResponse is missing Id");

            if (Raw.Type != PublicKeyCredentialType.PublicKey)
                throw new Fido2VerificationException("AttestationResponse is missing type with value 'public-key'");

            if (null == AttestationObject.AuthData || 0 == AttestationObject.AuthData.Length)
                throw new Fido2VerificationException("Missing or malformed authData");

            var authData = new AuthenticatorData(AttestationObject.AuthData);
            // 6
            //todo:  Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection 
            // over which the assertion was obtained.If Token Binding was used on that TLS connection, 
            // also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
            // This is done in BaseVerify.
            // TODO: test that implmentation

            // 7
            // Compute the hash of response.clientDataJSON using SHA - 256.
            byte[] clientDataHash, rpIdHash;
            using (var sha = CryptoUtils.GetHasher(HashAlgorithmName.SHA256))
            {
                clientDataHash = sha.ComputeHash(Raw.Response.ClientDataJson);
                rpIdHash = sha.ComputeHash(Encoding.UTF8.GetBytes(originalOptions.Rp.Id));
            }
            
            // 9 
            // Verify that the RP ID hash in authData is indeed the SHA - 256 hash of the RP ID expected by the RP.
            if (false == authData.RpIdHash.SequenceEqual(rpIdHash))
                throw new Fido2VerificationException("Hash mismatch RPID");

            // 10
            // Verify that the User Present bit of the flags in authData is set.
            if (false == authData.UserPresent)
                throw new Fido2VerificationException("User Present flag not set in authenticator data");

            // 11 
            // If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
            // see authData.UserVerified

            // 12
            // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected
            // todo: Implement sort of like this: ClientExtensions.Keys.Any(x => options.extensions.contains(x);

            if (false == authData.AttestedCredentialDataPresent)
                throw new Fido2VerificationException("Attestation flag not set on attestation data");

            // 13
            // Determine the attestation statement format by performing a US ASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].
            // https://www.w3.org/TR/webauthn/#defined-attestation-formats
            AttestationFormat.AttestationFormat verifier;
            switch (AttestationObject.Fmt)
            {
                // 14
                // validate the attStmt
                case "none":
                        // https://www.w3.org/TR/webauthn/#none-attestation
                        verifier = new None(AttestationObject.AttStmt, AttestationObject.AuthData, clientDataHash);
                    break;

                case "tpm":
                        // https://www.w3.org/TR/webauthn/#tpm-attestation
                        verifier = new Tpm(AttestationObject.AttStmt, AttestationObject.AuthData, clientDataHash);
                    break;

                case "android-key":
                        // https://www.w3.org/TR/webauthn/#android-key-attestation
                        verifier = new AndroidKey(AttestationObject.AttStmt, AttestationObject.AuthData, clientDataHash);
                    break;

                case "android-safetynet":
                        // https://www.w3.org/TR/webauthn/#android-safetynet-attestation
                        verifier = new AndroidSafetyNet(AttestationObject.AttStmt, AttestationObject.AuthData, clientDataHash, config.TimestampDriftTolerance);
                    break;

                case "fido-u2f":
                        // https://www.w3.org/TR/webauthn/#fido-u2f-attestation
                        verifier = new FidoU2f(AttestationObject.AttStmt, AttestationObject.AuthData, clientDataHash, metadataService);
                    break;

                case "packed":
                        // https://www.w3.org/TR/webauthn/#packed-attestation
                        verifier = new Packed(AttestationObject.AttStmt, AttestationObject.AuthData, clientDataHash, metadataService);
                    break;

                default: throw new Fido2VerificationException("Missing or unknown attestation type");
            }

            verifier.Verify();
            /* 
             * 15
             * If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) 
             * for that attestation type and attestation statement format fmt, from a trusted source or from policy. 
             * For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, 
             * using the aaguid in the attestedCredentialData in authData.
             * */

            /* 
             * 16 
             * Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows: https://www.w3.org/TR/webauthn/#registering-a-new-credential
             * */
            // use aaguid (authData.AttData.Aaguid) to find root certs in metadata
            // use root plus trustPath to build trust chain
            // implemented for AttestationObject.Fmt == "packed" in packed specific verifier

            /* 
             * 17
             * Check that the credentialId is not yet registered to any other user.
             * If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.
             * */
            if (false == await isCredentialIdUniqueToUser(new IsCredentialIdUniqueToUserParams(authData.AttData.CredentialID, originalOptions.User)))
            {
                throw new Fido2VerificationException("CredentialId is not unique to this user");
            }

            /* 
             * 18
             * If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the Relying Party's system.
             * */
            // This is handled by code att call site and result object.


            /* 
             * 19
             * If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.
             * NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see §6.3.3 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.
             * */

            var result = new AttestationVerificationSuccess()
            {
                CredentialId = authData.AttData.CredentialID,
                PublicKey = authData.AttData.CredentialPublicKey,
                User = originalOptions.User,
                Counter = BitConverter.ToUInt32(authData.SignCount.Reverse().ToArray(), 0),
                CredType = AttestationObject.Fmt,
                Aaguid = authData.AttData.GuidAaguid
            };            

            return result;
        }

        /// <summary>
        /// The AttestationObject after CBOR parsing
        /// </summary>
        public class ParsedAttestationObject
        {
            public string Fmt { get; set; }
            public byte[] AuthData { get; set; }
            public CBORObject AttStmt { get; set; }
        }
    }
}
