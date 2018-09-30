using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib.Objects;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace Fido2NetLib
{
    /// <summary>
    /// The AuthenticatorAttestationResponse interface represents the authenticator's response to a client’s request for the creation of a new public key credential.
    /// It contains information about the new credential that can be used to identify it for later use, and metadata that can be used by the Relying Party to assess the characteristics of the credential during registration.
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
            if (null == rawResponse || null == rawResponse.Response) throw new Fido2VerificationException("Expected rawResponse, got null");
            
            if (null == rawResponse.Response.AttestationObject || 0 == rawResponse.Response.AttestationObject.Length) throw new Fido2VerificationException("Missing AttestationObject");
            PeterO.Cbor.CBORObject cborAttestation = null;
            try
            {
                cborAttestation = PeterO.Cbor.CBORObject.DecodeFromBytes(rawResponse.Response.AttestationObject);
            }
            catch (PeterO.Cbor.CBORException)
            {
                throw new Fido2VerificationException("Malformed AttestationObject");
            }

            if (    null == cborAttestation["fmt"] ||
                    PeterO.Cbor.CBORType.TextString != cborAttestation["fmt"].Type || 
                    null == cborAttestation["attStmt"] ||
                    PeterO.Cbor.CBORType.Map != cborAttestation["attStmt"].Type || 
                    null == cborAttestation["authData"] ||
                    PeterO.Cbor.CBORType.ByteString != cborAttestation["authData"].Type
                    )   throw new Fido2VerificationException("Malformed AttestationObject");

            AuthenticatorAttestationResponse response = new AuthenticatorAttestationResponse(rawResponse.Response.ClientDataJson)
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

        public async Task<AttestationVerificationSuccess> VerifyAsync(CredentialCreateOptions originalOptions, string expectedOrigin, IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser, byte[] requestTokenBindingId)
        {
            AttestationType attnType;
            X509Certificate2[] trustPath = null;
            BaseVerify(expectedOrigin, originalOptions.Challenge, requestTokenBindingId);
            // verify challenge is same as we expected
            // verify origin
            // done in baseclass

            if (Type != "webauthn.create") throw new Fido2VerificationException("AttestationResponse is not type webauthn.create");

            if (Raw.Id == null || Raw.Id.Length == 0) throw new Fido2VerificationException("AttestationResponse is missing Id");

            if (Raw.Type != "public-key") throw new Fido2VerificationException("AttestationResponse is missing type with value 'public-key'");

            if (null == AttestationObject.AuthData || 0 == AttestationObject.AuthData.Length) throw new Fido2VerificationException("Missing or malformed authData");
            AuthenticatorData authData = new AuthenticatorData(AttestationObject.AuthData);
            // 6
            //todo:  Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained.If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
            // This id done in BaseVerify.
            // todo: test that implmentation

            // 7
            // Compute the hash of response.clientDataJSON using SHA - 256.
            byte[] hashedClientDataJson;
            byte[] hashedRpId;
            using (var sha = SHA256.Create())
            {
                hashedClientDataJson = sha.ComputeHash(Raw.Response.ClientDataJson);
                hashedRpId = sha.ComputeHash(Encoding.UTF8.GetBytes(originalOptions.Rp.Id));
            }
            
            // 9 
            // Verify that the RP ID hash in authData is indeed the SHA - 256 hash of the RP ID expected by the RP.
            if (false == authData.RpIdHash.SequenceEqual(hashedRpId)) throw new Fido2VerificationException("Hash mismatch RPID");

            // 10
            // Verify that the User Present bit of the flags in authData is set.
            if (false == authData.UserPresent) throw new Fido2VerificationException("User Present flag not set in authenticator data");

            // 11 
            // If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
            var userVerified = authData.UserVerified;

            // 12
            // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected
            // todo: Implement sort of like this: ClientExtensions.Keys.Any(x => options.extensions.contains(x);

            // A COSEAlgorithmIdentifier containing the identifier of the algorithm used to generate the attestation signature
            var alg = AttestationObject.AttStmt["alg"];
            // A byte string containing the attestation signature
            var sig = AttestationObject.AttStmt["sig"];
            // The elements of this array contain attestnCert and its certificate chain, each encoded in X.509 format
            var x5c = AttestationObject.AttStmt["x5c"];
            // The identifier of the ECDAA-Issuer public key
            var ecdaaKeyId = AttestationObject.AttStmt["ecdaaKeyId"];

            if (false == authData.AttestedCredentialDataPresent) throw new Fido2VerificationException("Attestation flag not set on attestation data");
            var credentialId = authData.AttData.CredentialID;
            var credentialPublicKeyBytes = authData.AttData.CredentialPublicKey.ToArray();
            PeterO.Cbor.CBORObject credentialPublicKey = null;
            var coseKty = 0;
            var coseAlg = 0;
            try
            {
                credentialPublicKey = PeterO.Cbor.CBORObject.DecodeFromBytes(authData.AttData.CredentialPublicKey);
                coseKty = credentialPublicKey[PeterO.Cbor.CBORObject.FromObject(1)].AsInt32();
                coseAlg = credentialPublicKey[PeterO.Cbor.CBORObject.FromObject(3)].AsInt32();
            }
            catch (PeterO.Cbor.CBORException)
            {
                throw new Fido2VerificationException("Malformed credentialPublicKey");
            }
            byte[] data = new byte[AttestationObject.AuthData.Length + hashedClientDataJson.Length];
            Buffer.BlockCopy(AttestationObject.AuthData, 0, data, 0, AttestationObject.AuthData.Length);
            Buffer.BlockCopy(hashedClientDataJson, 0, data, AttestationObject.AuthData.Length, hashedClientDataJson.Length);
            // 13
            // Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].
            // https://www.w3.org/TR/webauthn/#defined-attestation-formats
            switch (AttestationObject.Fmt)
            {
                // 14
                // validate the attStmt

                case "none":
                    {
                        // https://www.w3.org/TR/webauthn/#none-attestation

                        if (0 != AttestationObject.AttStmt.Keys.Count && 0 != AttestationObject.AttStmt.Values.Count) throw new Fido2VerificationException("Attestation format none should have no attestation statement");
                        attnType = AttestationType.None;
                        trustPath = null;
                    }
                    break;

                case "tpm":
                    {
                        // https://www.w3.org/TR/webauthn/#tpm-attestation

                        if (null == sig || PeterO.Cbor.CBORType.ByteString != sig.Type || 0 == sig.GetByteString().Length) throw new Fido2VerificationException("Invalid TPM attestation signature");
                        if ("2.0" != AttestationObject.AttStmt["ver"].AsString()) throw new Fido2VerificationException("FIDO2 only supports TPM 2.0");

                        // Verify that the public key specified by the parameters and unique fields of pubArea is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData
                        PubArea pubArea = null;
                        if (null != AttestationObject.AttStmt["pubArea"] && PeterO.Cbor.CBORType.ByteString == AttestationObject.AttStmt["pubArea"].Type && 0 != AttestationObject.AttStmt["pubArea"].GetByteString().Length)
                        {
                            pubArea = new PubArea(AttestationObject.AttStmt["pubArea"].GetByteString());
                        }

                        var coseMod = credentialPublicKey[PeterO.Cbor.CBORObject.FromObject(-1)].GetByteString(); // modulus 
                        var coseExp = credentialPublicKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString(); // exponent

                        if (null == pubArea || null == pubArea.Unique || 0 == pubArea.Unique.Length) throw new Fido2VerificationException("Missing or malformed pubArea");
                        if (!coseMod.ToArray().SequenceEqual(pubArea.Unique.ToArray())) throw new Fido2VerificationException("Public key mismatch");
                        if ((coseExp[0] + (coseExp[1] << 8) + (coseExp[2] << 16)) != pubArea.Exponent) throw new Fido2VerificationException("Public key exponent mismatch");

                        // Concatenate authenticatorData and clientDataHash to form attToBeSigned.
                        // see data variable

                        // Validate that certInfo is valid
                        CertInfo certInfo = null;
                        if (null != AttestationObject.AttStmt["certInfo"] && PeterO.Cbor.CBORType.ByteString == AttestationObject.AttStmt["certInfo"].Type && 0 != AttestationObject.AttStmt["certInfo"].GetByteString().Length)
                        {
                            certInfo = new CertInfo(AttestationObject.AttStmt["certInfo"].GetByteString());
                        }
                        if (null == certInfo || null == certInfo.ExtraData || 0 == certInfo.ExtraData.Length) throw new Fido2VerificationException("CertInfo invalid parsing TPM format attStmt");
                        // Verify that magic is set to TPM_GENERATED_VALUE and type is set to TPM_ST_ATTEST_CERTIFY 
                        // handled in parser, see certInfo.Magic

                        // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg"
                        if (null == alg || PeterO.Cbor.CBORType.Number != alg.Type || false == AuthDataHelper.algMap.ContainsKey(alg.AsInt32())) throw new Fido2VerificationException("Invalid TPM attestation algorithm");
                        if (!AuthDataHelper.GetHasher(AuthDataHelper.algMap[alg.AsInt32()]).ComputeHash(data).SequenceEqual(certInfo.ExtraData)) throw new Fido2VerificationException("Hash value mismatch extraData and attToBeSigned");

                        // Verify that attested contains a TPMS_CERTIFY_INFO structure, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea 
                        if (false == AuthDataHelper.GetHasher(AuthDataHelper.algMap[(int)certInfo.Alg]).ComputeHash(pubArea.Raw).SequenceEqual(certInfo.AttestedName)) throw new Fido2VerificationException("Hash value mismatch attested and pubArea");

                        // If x5c is present, this indicates that the attestation type is not ECDAA
                        if (null != x5c && PeterO.Cbor.CBORType.Array == x5c.Type && 0 != x5c.Count)
                        {
                            if (null == x5c.Values || 0 == x5c.Values.Count || PeterO.Cbor.CBORType.ByteString != x5c.Values.First().Type || 0 == x5c.Values.First().GetByteString().Length) throw new Fido2VerificationException("Malformed x5c in TPM attestation");

                            // Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
                            var aikCert = new X509Certificate2(x5c.Values.First().GetByteString());
                            var aikPublicKey = aikCert.GetRSAPublicKey();
                            // TODO: will TPM always be using this signature padding, or could is use PSS in some cases?
                            // TODO: Not only can it be different signature padding, it can be EC2. Have not seen, but in spec.
                            if (true != aikPublicKey.VerifyData(certInfo.Raw, sig.GetByteString(), AuthDataHelper.algMap[alg.AsInt32()], RSASignaturePadding.Pkcs1)) throw new Fido2VerificationException("Bad signature in TPM with aikCert");

                            // Verify that aikCert meets the TPM attestation statement certificate requirements
                            // https://www.w3.org/TR/webauthn/#tpm-cert-requirements
                            // Version MUST be set to 3
                            if (3 != aikCert.Version) throw new Fido2VerificationException("aikCert must be V3");

                            // Subject field MUST be set to empty - they actually mean subject name
                            if (0 != aikCert.SubjectName.Name.Length) throw new Fido2VerificationException("aikCert subject must be empty");

                            // The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
                            // https://www.w3.org/TR/webauthn/#tpm-cert-requirements
                            var SAN = AuthDataHelper.SANFromAttnCertExts(aikCert.Extensions);
                            if (null == SAN || 0 == SAN.Length) throw new Fido2VerificationException("SAN missing from TPM attestation certificate");
                            // From https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
                            // The issuer MUST include TPM manufacturer, TPM part number and TPM firmware version, using the directoryNameform within the GeneralName structure. The ASN.1 encoding is specified in section 3.1.2 TPM Device Attributes. In accordance with RFC 5280[11], this extension MUST be critical if subject is empty and SHOULD be non-critical if subject is non-empty.   
                            // Best I can figure to do for now?
                            if (false == SAN.Contains("TPMManufacturer") || false == SAN.Contains("TPMModel") || false == SAN.Contains("TPMVersion")) throw new Fido2VerificationException("SAN missing TPMManufacturer, TPMModel, or TPMVersopm from TPM attestation certificate");
                            // The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
                            // OID is 2.23.133.8.3
                            var EKU = AuthDataHelper.EKUFromAttnCertExts(aikCert.Extensions);
                            if (null == EKU || 0 != EKU.CompareTo("Attestation Identity Key Certificate (2.23.133.8.3)")) throw new Fido2VerificationException("Invalid EKU on AIK certificate");

                            // The Basic Constraints extension MUST have the CA component set to false.
                            if (AuthDataHelper.IsAttnCertCACert(aikCert.Extensions)) throw new Fido2VerificationException("aikCert Basic Constraints extension CA component must be false");

                            // If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData
                            var aaguid = AuthDataHelper.AaguidFromAttnCertExts(aikCert.Extensions);
                            if ((null != aaguid) && (!aaguid.SequenceEqual(Guid.Empty.ToByteArray())) && (!aaguid.SequenceEqual(authData.AttData.Aaguid.ToArray()))) throw new Fido2VerificationException("aaguid malformed");

                            // If successful, return attestation type AttCA and attestation trust path x5c.
                            attnType = AttestationType.AttCa;
                            trustPath = x5c.Values
                                .Select(x =>  new X509Certificate2(x.GetByteString()))
                                .ToArray();
                        }
                        // If ecdaaKeyId is present, then the attestation type is ECDAA
                        else if (null != ecdaaKeyId)
                        {
                            // Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo
                            // https://www.w3.org/TR/webauthn/#biblio-fidoecdaaalgorithm
                            throw new Fido2VerificationException("ECDAA support for TPM attestation is not yet implemented");
                            // If successful, return attestation type ECDAA and the identifier of the ECDAA-Issuer public key ecdaaKeyId.
                            //attnType = AttestationType.ECDAA;
                            //trustPath = ecdaaKeyId;
                        }
                        else throw new Fido2VerificationException("Neither x5c nor ECDAA were found in the TPM attestation statement");
                    }
                    break;

                case "android-key":
                    {
                        // https://www.w3.org/TR/webauthn/#android-key-attestation

                        // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields
                        if (0 == AttestationObject.AttStmt.Keys.Count || 0 == AttestationObject.AttStmt.Values.Count) throw new Fido2VerificationException("Attestation format packed must have attestation statement");
                        if (null == sig || PeterO.Cbor.CBORType.ByteString != sig.Type || 0 == sig.GetByteString().Length) throw new Fido2VerificationException("Invalid packed attestation signature");
                        // 2a. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
                        // using the attestation public key in attestnCert with the algorithm specified in alg
                        if (null == x5c && PeterO.Cbor.CBORType.Array != x5c.Type && 0 == x5c.Count) throw new Fido2VerificationException("Malformed x5c in android-key attestation");
                        if (null == x5c.Values || 0 == x5c.Values.Count || PeterO.Cbor.CBORType.ByteString != x5c.Values.First().Type || 0 == x5c.Values.First().GetByteString().Length) throw new Fido2VerificationException("Malformed x5c in android-key attestation");
                        X509Certificate2 androidKeyCert = null;
                        ECDsaCng androidKeyPubKey = null;
                        try
                        {
                            androidKeyCert = new X509Certificate2(x5c.Values.First().GetByteString());
                            androidKeyPubKey = (ECDsaCng)androidKeyCert.GetECDsaPublicKey(); // attestation public key
                        }
                        catch (Exception ex)
                        {
                            throw new Fido2VerificationException("Failed to extract public key from android key" + ex.Message);
                        }
                        if (null == alg || PeterO.Cbor.CBORType.Number != alg.Type || false == AuthDataHelper.algMap.ContainsKey(alg.AsInt32())) throw new Fido2VerificationException("Invalid attestation algorithm");
                        if (true != androidKeyPubKey.VerifyData(data, AuthDataHelper.SigFromEcDsaSig(sig.GetByteString()), AuthDataHelper.algMap[alg.AsInt32()])) throw new Fido2VerificationException("Invalid android key signature");
                        var cng = ECDsaCng.Create(new ECParameters
                        {
                            Curve = ECCurve.NamedCurves.nistP256,
                            Q = new ECPoint
                            {
                                X = credentialPublicKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString(),
                                Y = credentialPublicKey[PeterO.Cbor.CBORObject.FromObject(-3)].GetByteString()
                            }
                        });
                        // Verify that the public key in the first certificate in in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
                        if (true != cng.VerifyData(data, AuthDataHelper.SigFromEcDsaSig(sig.GetByteString()), AuthDataHelper.algMap[alg.AsInt32()])) throw new Fido2VerificationException("Invalid android key signature");

                        // Verify that in the attestation certificate extension data:
                        var attExtBytes = AuthDataHelper.AttestationExtensionBytes(androidKeyCert.Extensions);

                        // 1. The value of the attestationChallenge field is identical to clientDataHash.
                        var attestationChallenge = AuthDataHelper.GetAttestationChallenge(attExtBytes);
                        if (false == hashedClientDataJson.SequenceEqual(attestationChallenge)) throw new Fido2VerificationException("Mismatched between attestationChallenge and hashedClientDataJson verifying android key attestation certificate extension");
                        
                        // 2. The AuthorizationList.allApplications field is not present, since PublicKeyCredential MUST be bound to the RP ID.
                        if (true == AuthDataHelper.FindAllApplicationsField(attExtBytes)) throw new Fido2VerificationException("Found all applications field in android key attestation certificate extension");
                        
                        // 3. The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED ( which == 0).
                        if (false == AuthDataHelper.IsOriginGenerated(attExtBytes)) throw new Fido2VerificationException("Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension");
                        
                        // 4. The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN (which == 2).
                        if (false == AuthDataHelper.IsPurposeSign(attExtBytes)) throw new Fido2VerificationException("Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension");

                        attnType = AttestationType.Basic;
                        trustPath = x5c.Values
                            .Select(x => new X509Certificate2(x.GetByteString()))
                            .ToArray();
                    }
                    break;

                case "android-safetynet":
                    { 
                        // https://www.w3.org/TR/webauthn/#android-safetynet-attestation

                        // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields
                        if ((PeterO.Cbor.CBORType.TextString != AttestationObject.AttStmt["ver"].Type) || (0 == AttestationObject.AttStmt["ver"].AsString().Length)) throw new Fido2VerificationException("Invalid version in SafetyNet data");

                        // Verify that response is a valid SafetyNet response of version ver
                        var ver = AttestationObject.AttStmt["ver"].AsString();

                        if ((PeterO.Cbor.CBORType.ByteString != AttestationObject.AttStmt["response"].Type) || (0 == AttestationObject.AttStmt["response"].GetByteString().Length)) throw new Fido2VerificationException("Invalid response in SafetyNet data");
                        var response = AttestationObject.AttStmt["response"].GetByteString();
                        var signedAttestationStatement = Encoding.UTF8.GetString(response);
                        var jwtToken = new JwtSecurityToken(signedAttestationStatement);
                        X509SecurityKey[] keys = (jwtToken.Header["x5c"] as JArray)
                            .Values<string>()
                            .Select(x => new X509SecurityKey(
                                new X509Certificate2(Convert.FromBase64String(x))))
                            .ToArray();
                        if ((null == keys) || (0 == keys.Count())) throw new Fido2VerificationException("SafetyNet attestation missing x5c");
                        var validationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKeys = keys
                        };

                        var tokenHandler = new JwtSecurityTokenHandler();
                        SecurityToken validatedToken;

                        tokenHandler.ValidateToken(
                            signedAttestationStatement,
                            validationParameters,
                            out validatedToken);

                        if (false == (validatedToken.SigningKey is X509SecurityKey)) throw new Fido2VerificationException("Safetynet signing key invalid");

                        var nonce = "";
                        var payload = false;
                        foreach (var claim in jwtToken.Claims)
                        {
                            if (("nonce" == claim.Type) && ("http://www.w3.org/2001/XMLSchema#string" == claim.ValueType) && (0 != claim.Value.Length)) nonce = claim.Value;
                            if (("ctsProfileMatch" == claim.Type) && ("http://www.w3.org/2001/XMLSchema#boolean" == claim.ValueType))
                            {
                                payload = bool.Parse(claim.Value);
                            }
                            if (("timestampMs" == claim.Type) && ("http://www.w3.org/2001/XMLSchema#integer64" == claim.ValueType))
                            {
                                DateTime dt = DateTimeHelper.UnixEpoch.AddMilliseconds(double.Parse(claim.Value));
                                if ((DateTime.UtcNow < dt) || (DateTime.UtcNow.AddMinutes(-1) > dt)) throw new Fido2VerificationException("Android SafetyNet timestampMs must be between one minute ago and now");
                            }
                        }

                        // Verify that the nonce in the response is identical to the SHA-256 hash of the concatenation of authenticatorData and clientDataHash
                        if ("" == nonce) throw new Fido2VerificationException("Nonce value not found in Android SafetyNet attestation");
                        if (!AuthDataHelper.GetHasher(HashAlgorithmName.SHA256).ComputeHash(data).SequenceEqual(Convert.FromBase64String(nonce))) throw new Fido2VerificationException("Android SafetyNet hash value mismatch");

                        // Verify that the attestation certificate is issued to the hostname "attest.android.com"
                        if (false == ("attest.android.com").Equals((validatedToken.SigningKey as X509SecurityKey).Certificate.GetNameInfo(X509NameType.DnsName, false))) throw new Fido2VerificationException("Safetynet DnsName is not attest.android.com");

                        // Verify that the ctsProfileMatch attribute in the payload of response is true
                        if (true != payload) throw new Fido2VerificationException("Android SafetyNet ctsProfileMatch must be true");

                        attnType = AttestationType.Basic;
                        trustPath = (jwtToken.Header["x5c"] as JArray)
                            .Values<string>()
                            .Select(x => new X509Certificate2(Convert.FromBase64String(x)))
                            .ToArray();
                    }
                    break;

                case "fido-u2f":
                    {
                        // https://www.w3.org/TR/webauthn/#fido-u2f-attestation

                        // verify that aaguid is 16 empty bytes (note: required by fido2 conformance testing, could not find this in spec?)
                        if (false == authData.AttData.Aaguid.SequenceEqual(Guid.Empty.ToByteArray())) throw new Fido2VerificationException("Aaguid was not empty parsing fido-u2f atttestation statement");

                        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
                        if (null == x5c || PeterO.Cbor.CBORType.Array != x5c.Type || x5c.Count != 1) throw new Fido2VerificationException("Malformed x5c in fido - u2f attestation");

                        // 2a. the attestation certificate attestnCert MUST be the first element in the array
                        if (null == x5c.Values || 0 == x5c.Values.Count || PeterO.Cbor.CBORType.ByteString != x5c.Values.First().Type || 0 == x5c.Values.First().GetByteString().Length) throw new Fido2VerificationException("Malformed x5c in fido-u2f attestation");
                        var cert = new X509Certificate2(x5c.Values.First().GetByteString());

                        // 2b. If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error
                        var pubKey = (ECDsaCng)cert.GetECDsaPublicKey();
                        if (CngAlgorithm.ECDsaP256 != pubKey.Key.Algorithm) throw new Fido2VerificationException("attestation certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve");

                        // 3. Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData
                        // done above

                        // 4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to CTAP1/U2F public Key format
                        var publicKeyU2F = AuthDataHelper.U2FKeyFromCOSEKey(credentialPublicKey);

                        // 5. Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
                        var verificationData = new byte[1] { 0x00 };
                        verificationData = verificationData.Concat(hashedRpId).Concat(hashedClientDataJson).Concat(credentialId).Concat(publicKeyU2F.ToArray()).ToArray();

                        // 6. Verify the sig using verificationData and certificate public key
                        if (null == sig || PeterO.Cbor.CBORType.ByteString != sig.Type || 0 == sig.GetByteString().Length) throw new Fido2VerificationException("Invalid fido-u2f attestation signature");
                        var ecsig = AuthDataHelper.SigFromEcDsaSig(sig.GetByteString());
                        if (null == ecsig) throw new Fido2VerificationException("Failed to decode fido-u2f attestation signature from ASN.1 encoded form");
                        if (true != pubKey.VerifyData(verificationData, ecsig, AuthDataHelper.algMap[coseAlg])) throw new Fido2VerificationException("Invalid fido-u2f attestation signature");
                        attnType = AttestationType.Basic;
                        trustPath = x5c.Values
                            .Select(x => new X509Certificate2(x.GetByteString()))
                            .ToArray();
                    }
                    break;

                case "packed":
                    {
                        // https://www.w3.org/TR/webauthn/#packed-attestation

                        // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
                        if (0 == AttestationObject.AttStmt.Keys.Count || 0 == AttestationObject.AttStmt.Values.Count) throw new Fido2VerificationException("Attestation format packed must have attestation statement");
                        if (null == sig || PeterO.Cbor.CBORType.ByteString != sig.Type || 0 == sig.GetByteString().Length) throw new Fido2VerificationException("Invalid packed attestation signature");
                        if (null == alg || PeterO.Cbor.CBORType.Number != alg.Type) throw new Fido2VerificationException("Invalid packed attestation algorithm");
                        byte[] packedParsedSignature = null;
                        if (-7 == alg.AsInt32() || -35 == alg.AsInt32() || -36 == alg.AsInt32())
                        {
                            packedParsedSignature = AuthDataHelper.SigFromEcDsaSig(sig.GetByteString());
                        }
                        else packedParsedSignature = sig.GetByteString();

                        // If x5c is present, this indicates that the attestation type is not ECDAA
                        if (null != x5c)
                        {
                            if (PeterO.Cbor.CBORType.Array != x5c.Type || 0 == x5c.Count || null != ecdaaKeyId) throw new Fido2VerificationException("Malformed x5c array in packed attestation statement");
                            IEnumerator<PeterO.Cbor.CBORObject> enumerator = x5c.Values.GetEnumerator();
                            while (enumerator.MoveNext())
                            {
                                if (null == enumerator || null == enumerator.Current || PeterO.Cbor.CBORType.ByteString != enumerator.Current.Type || 0 == enumerator.Current.GetByteString().Length) throw new Fido2VerificationException("Malformed x5c cert found in packed attestation statement");
                                var x5ccert = new X509Certificate2(enumerator.Current.GetByteString());
                                if (DateTime.UtcNow < x5ccert.NotBefore || DateTime.UtcNow > x5ccert.NotAfter) throw new Fido2VerificationException("Packed signing certificate expired or not yet valid");
                            }

                            // The attestation certificate attestnCert MUST be the first element in the array.
                            var attestnCert = new X509Certificate2(x5c.Values.First().GetByteString());

                            // 2a. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
                            // using the attestation public key in attestnCert with the algorithm specified in alg
                            var packedPubKey = (ECDsaCng)attestnCert.GetECDsaPublicKey(); // attestation public key
                            if (null == alg || PeterO.Cbor.CBORType.Number != alg.Type || false == AuthDataHelper.algMap.ContainsKey(alg.AsInt32())) throw new Fido2VerificationException("Invalid attestation algorithm");
                            if (true != packedPubKey.VerifyData(data, packedParsedSignature, AuthDataHelper.algMap[alg.AsInt32()])) throw new Fido2VerificationException("Invalid full packed signature");

                            // Verify that attestnCert meets the requirements in https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements
                            // 2b. Version MUST be set to 3
                            if (3 != attestnCert.Version) throw new Fido2VerificationException("Packed x5c attestation certificate not V3");

                            // Subject field MUST contain C, O, OU, CN
                            // OU must match "Authenticator Attestation"
                            if (true != AuthDataHelper.IsValidPackedAttnCertSubject(attestnCert.Subject)) throw new Fido2VerificationException("Invalid attestation cert subject");

                            // 2c. If the related attestation root certificate is used for multiple authenticator models, 
                            // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING
                            // verify that the value of this extension matches the aaguid in authenticatorData
                            var aaguid = AuthDataHelper.AaguidFromAttnCertExts(attestnCert.Extensions);
                            if (aaguid != null && !aaguid.SequenceEqual(authData.AttData.Aaguid.ToArray())) throw new Fido2VerificationException("aaguid present in packed attestation but does not match aaguid from authData");

                            // 2d. The Basic Constraints extension MUST have the CA component set to false
                            if (AuthDataHelper.IsAttnCertCACert(attestnCert.Extensions)) throw new Fido2VerificationException("Attestion certificate has CA cert flag present");

                            // id-fido-u2f-ce-transports 
                            var u2ftransports = AuthDataHelper.U2FTransportsFromAttnCert(attestnCert.Extensions);
                            attnType = AttestationType.Basic;
                            trustPath = x5c.Values
                            .Select(x => new X509Certificate2(x.GetByteString()))
                            .ToArray();
                        }
                        // If ecdaaKeyId is present, then the attestation type is ECDAA
                        else if (null != ecdaaKeyId)
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
                            if (alg.AsInt32() != coseAlg) throw new Fido2VerificationException("Algorithm mismatch between credential public key and authenticator data in self attestation statement");
                            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg
                            if (true != AuthDataHelper.VerifySigWithCoseKey(data, credentialPublicKey, sig.GetByteString())) throw new Fido2VerificationException("Failed to validate signature");

                            // If successful, return attestation type Self and empty attestation trust path.
                            attnType = AttestationType.Self;
                            trustPath = null;
                        }
                    }
                    break;

                default: throw new Fido2VerificationException("Missing or unknown attestation type");
            }

            /* 
             * 15
             * If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
             * */
            // MetadataService

            /* 
             * 16 
             * Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows: https://www.w3.org/TR/webauthn/#registering-a-new-credential
             * */
            // todo: implement (this is not for attfmt none)
            // use aaguid (authData.AttData.Aaguid) to find root certs in metadata
            // use root plus trustPath to build trust chain
            
            MetadataTOCPayloadEntry entry = null;
            var metadata = MDSMetadata.Instance();
            if (null != metadata)
            {
                if (true == metadata.payload.ContainsKey(authData.AttData.GuidAaguid))
                { 
                    entry = metadata.payload[authData.AttData.GuidAaguid];
                }
                if (null != entry)
                {
                    if (entry.Hash != entry.MetadataStatement.Hash) throw new Fido2VerificationException("Authenticator metadata statement has invalid hash");
                    if (null != entry.MetadataStatement)
                    {
                        var hasBasicFull = entry.MetadataStatement.AttestationTypes.Contains((ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL);
                        if (false == hasBasicFull &&
                            null != trustPath && trustPath.FirstOrDefault().Subject != trustPath.FirstOrDefault().Issuer) throw new Fido2VerificationException("Attestation with full attestation from authentictor that does not support full attestation");
                    }
                    if (null != entry.StatusReports)
                    {
                        foreach (StatusReport report in entry.StatusReports)
                        {
                            if (true == Enum.IsDefined(typeof(UndesiredAuthenticatorStatus), report.Status)) throw new Fido2VerificationException("Authenticator found with undesirable status");
                        }
                    }
                }
            }
            
            /* 
             * 17
             * Check that the credentialId is not yet registered to any other user.
             * If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.
             * */
            if (false == await isCredentialIdUniqueToUser(new IsCredentialIdUniqueToUserParams(credentialId, originalOptions.User)))
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
            // todo: implement (this is not for attfmt none)

            var result = new AttestationVerificationSuccess()
            {
                CredentialId = credentialId,
                PublicKey = credentialPublicKeyBytes,
                User = originalOptions.User,
                Counter = BitConverter.ToUInt32(authData.SignCount.ToArray().Reverse().ToArray(), 0)
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
            public PeterO.Cbor.CBORObject AttStmt { get; set; }
        }
    }
}
