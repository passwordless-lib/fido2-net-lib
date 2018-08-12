using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
namespace fido2NetLib
{
    /// <summary>
    /// The AuthenticatorAttestationResponse interface represents the authenticator's response to a client’s request for the creation of a new public key credential.
    /// It contains information about the new credential that can be used to identify it for later use, and metadata that can be used by the Relying Party to assess the characteristics of the credential during registration.
    /// </summary>
    public class AuthenticatorAttestationResponse : AuthenticatorResponse
    {
        public static readonly Dictionary<int, HashAlgorithmName> algMap = new Dictionary<int, HashAlgorithmName>
        {
            {-7, HashAlgorithmName.SHA256},
            {-35, HashAlgorithmName.SHA384 },
            {-36, HashAlgorithmName.SHA512 }
        };

        private AuthenticatorAttestationResponse(byte[] clientDataJson) : base(clientDataJson)
        {
        }

        public string HashAlgorithm { get; set; }
        public Dictionary<string, object> ClientExtensions { get; set; }

        public ParsedAttestionObject AttestionObject { get; set; }
        public AuthenticatorAttestationRawResponse Raw { get; private set; }

        public static AuthenticatorAttestationResponse Parse(AuthenticatorAttestationRawResponse rawResponse)
        {
            var rawAttestionObj = rawResponse.Response.AttestationObject;
            var cborAttestion = PeterO.Cbor.CBORObject.DecodeFromBytes(rawAttestionObj);

            var response = new AuthenticatorAttestationResponse(rawResponse.Response.ClientDataJson)
            {
                Raw = rawResponse,
                AttestionObject = new ParsedAttestionObject()
                {
                    Fmt = cborAttestion["fmt"].AsString(),
                    AttStmt = cborAttestion["attStmt"], // convert to dictionary?
                    AuthData = cborAttestion["authData"].GetByteString()
                }
            };

            return response;
        }

        public AttestationVerificationData Verify(CredentialCreateOptions options, string expectedOrigin, Fido2NetLib.isCredentialIdUniqueToUserDelegate isCredentialIdUniqueToUser)
        {
            var result = new AttestationVerificationData();

            BaseVerify(expectedOrigin, options.Challenge);
            // verify challenge is same as we expected
            // verify origin
            // done in baseclass

            if (Type != "webauthn.create") throw new Fido2VerificationException();


            // 6
            //todo:  Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained.If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.

            // 7
            // Compute the hash of response.clientDataJSON using SHA - 256.
            byte[] hashedClientDataJson;
            byte[] hashedRpId;
            using (var sha = SHA256.Create())
            {
                hashedClientDataJson = sha.ComputeHash(Raw.Response.ClientDataJson);
                hashedRpId = sha.ComputeHash(Encoding.UTF8.GetBytes(options.Rp.Id));
            }

            // 9 
            // Verify that the RP ID hash in authData is indeed the SHA - 256 hash of the RP ID expected by the RP.
            var hash = AuthDataHelper.GetRpIdHash(AttestionObject.AuthData);
            if (!hash.SequenceEqual(hashedRpId)) throw new Fido2VerificationException();

            // 10
            // Verify that the User Present bit of the flags in authData is set.
            if (!AuthDataHelper.IsUserPresent(AttestionObject.AuthData)) throw new Fido2VerificationException();

            // 11 
            // If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
            var userVerified = AuthDataHelper.IsUserVerified(AttestionObject.AuthData);

            // 12
            // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected
            // todo: Implement sort of like this: ClientExtensions.Keys.Any(x => options.extensions.contains(x);

            // A COSEAlgorithmIdentifier containing the identifier of the algorithm used to generate the attestation signature
            var alg = AttestionObject.AttStmt["alg"];
            // A byte string containing the attestation signature
            var sig = AttestionObject.AttStmt["sig"];
            // The elements of this array contain attestnCert and its certificate chain, each encoded in X.509 format
            var x5c = AttestionObject.AttStmt["x5c"];
            // The identifier of the ECDAA-Issuer public key
            var ecdaaKeyId = AttestionObject.AttStmt["ecdaaKeyId"];

            var attData = AuthDataHelper.GetAttestionData(AttestionObject.AuthData);

            var credentialId = attData.credId.ToArray();
            var credentialPublicKeyBytes = attData.credentialPublicKey.ToArray();
            var credentialPublicKey = PeterO.Cbor.CBORObject.DecodeFromBytes(credentialPublicKeyBytes);

            // 13
            // Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].
            // https://www.w3.org/TR/webauthn/#defined-attestation-formats
            switch (AttestionObject.Fmt)
            {
                // 14
                // validate the attStmt

                case "none":
                    if (0 != AttestionObject.AttStmt.Keys.Count && 0 != AttestionObject.AttStmt.Values.Count) throw new Fido2VerificationException("Attestation format none should have no attestation statement");
                    break;

                case "tpm":
                    // TODO: Implement TPM attestation validation
                    throw new Fido2VerificationException("Not yet implemented");
                    break;

                case "android-key":
                    // TODO: Implement Android Key attestation validation
                    throw new Fido2VerificationException("Not yet implemented");
                    break;

                case "android-safetynet":
                    // TODO: Implement Android SafetyNet attestation validation
                    throw new Fido2VerificationException("Not yet implemented");
                    break;

                case "fido-u2f":
                    var parsedSignature = AuthDataHelper.ParseSigData(sig.GetByteString());
                    // validate format
                    if (!(
                        AttestionObject.AttStmt.ContainsKey("x5c") &&
                        AttestionObject.AttStmt.ContainsKey("sig")
                        )) throw new Fido2VerificationException("Format is invalid");

                    // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
                    if (x5c.Count != 1) throw new Fido2VerificationException();

                    // 2a. the attestation certificate attestnCert MUST be the first element in the array
                    var cert = new X509Certificate2(x5c.Values.First().GetByteString());

                    // 2b. If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error
                    var pubKey = (ECDsaCng)cert.GetECDsaPublicKey();
                    if (CngAlgorithm.ECDsaP256 != pubKey.Key.Algorithm) throw new Fido2VerificationException();

                    // 3. Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData
                    // done above

                    // 4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to CTAP1/U2F public Key format
                    var publicKeyU2F = AuthDataHelper.U2FKeyFromCOSEKey(credentialPublicKey).publicKeyU2F.ToArray();
                    var COSE_alg = AuthDataHelper.U2FKeyFromCOSEKey(credentialPublicKey).COSE_alg;

                    // 5. Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
                    var verificationData = new byte[1] { 0x00 };
                    verificationData = verificationData.Concat(hashedRpId).Concat(hashedClientDataJson).Concat(credentialId).Concat(publicKeyU2F).ToArray();

                    // 6. Verify the sig using verificationData and certificate public key
                    if (true != pubKey.VerifyData(verificationData, parsedSignature.ToArray(), algMap[COSE_alg])) throw new Fido2VerificationException();
                    break;
                case "packed":

                    var packedParsedSignature = AuthDataHelper.ParseSigData(sig.GetByteString());
                    byte[] data = new byte[AttestionObject.AuthData.Length + hashedClientDataJson.Length];
                    AttestionObject.AuthData.CopyTo(data, 0);
                    hashedClientDataJson.CopyTo(data, AttestionObject.AuthData.Length);

                    // If x5c is present, this indicates that the attestation type is not ECDAA
                    if (null != x5c)
                    {
                        // The attestation certificate attestnCert MUST be the first element in the array.
                        var packedCert = new X509Certificate2(x5c.Values.First().GetByteString());

                        // 2a. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
                        // using the attestation public key in attestnCert with the algorithm specified in alg
                        var packedPubKey = (ECDsaCng)packedCert.GetECDsaPublicKey(); // attestation public key
                        if (true != packedPubKey.VerifyData(data, packedParsedSignature, algMap[alg.AsInt32()])) throw new Fido2VerificationException();

                        // 2b. Version MUST be set to 3
                        if (3 != packedCert.Version) throw new Fido2VerificationException();

                        // Subject field MUST contain C, O, OU, CN
                        // OU must match "Authenticator Attestation"
                        if (true != AuthDataHelper.IsValidPackedAttnCertSubject(packedCert.Subject)) throw new Fido2VerificationException("Invalid attestation cert subject");

                        // 2c. If the related attestation root certificate is used for multiple authenticator models, 
                        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING
                        // verify that the value of this extension matches the aaguid in authenticatorData
                        var aaguid = AuthDataHelper.AaguidFromAttnCertExts(packedCert.Extensions);
                        if (!aaguid.SequenceEqual(attData.aaguid.ToArray())) throw new Fido2VerificationException();

                        // 2d. The Basic Constraints extension MUST have the CA component set to false
                        if (AuthDataHelper.IsAttnCertCACert(packedCert.Extensions)) throw new Fido2VerificationException();

                        // id-fido-u2f-ce-transports 
                        var u2ftransports = AuthDataHelper.U2FTransportsFromAttnCert(packedCert.Extensions);
                    }
                    // If ecdaaKeyId is present, then the attestation type is ECDAA
                    else if (null != ecdaaKeyId)
                    {
                        var packedCert = new X509Certificate2(ecdaaKeyId.GetByteString());
                        var packedPubKey = (ECDsaCng)packedCert.GetECDsaPublicKey();
                        if (true != packedPubKey.VerifyData(data, packedParsedSignature.ToArray(), algMap[alg.AsInt32()])) throw new Fido2VerificationException();
                    }
                    // If neither x5c nor ecdaaKeyId is present, self attestation is in use
                    else
                    {
                        var packedCert = new X509Certificate2(attData.credentialPublicKey.ToArray());
                        var packedPubKey = (ECDsaCng)packedCert.GetECDsaPublicKey();
                        // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData
                        if (true != algMap[alg.AsInt32()].Equals(packedPubKey.Key.Algorithm)) throw new Fido2VerificationException();
                        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg
                        if (true != packedPubKey.VerifyData(data, packedParsedSignature, algMap[alg.AsInt32()])) throw new Fido2VerificationException();
                    }
                    break;

                default: throw new Fido2VerificationException("Missing or unknown attestation type");
            }

            /* 
             * 15
             * If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
             * */
            // todo: implement (this is not for attfmt none)

            /* 
             * 16 
             * Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows: https://www.w3.org/TR/webauthn/#registering-a-new-credential
             * */
            // todo: implement (this is not for attfmt none)

            /* 
             * 17
             * Check that the credentialId is not yet registered to any other user.
             * If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.
             * */
            if (!isCredentialIdUniqueToUser(credentialId, options.User)) { throw new Fido2VerificationException("CredentialId is not unique to this user"); }

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
            // todo: implement (this is not for attfmt none)

            result.CredentialId = credentialId;
            result.PublicKey = credentialPublicKeyBytes;

            return result;
        }

        /// <summary>
        /// The AttestationObject after CBOR parsing
        /// </summary>
        public class ParsedAttestionObject
        {
            public string Fmt { get; set; }
            public byte[] AuthData { get; set; }
            public PeterO.Cbor.CBORObject AttStmt { get; set; }
        }
    }
}
