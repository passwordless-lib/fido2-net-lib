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
    public class AuthenticatorAttestationResponse
    {
        public static readonly Dictionary<int, HashAlgorithmName> algLookup = new Dictionary<int, HashAlgorithmName>
        {
            {-7, HashAlgorithmName.SHA256},
            {-35, HashAlgorithmName.SHA384 },
            {-36, HashAlgorithmName.SHA512 }
        };
        public string Challenge { get; set; }
        public string HashAlgorithm { get; set; }
        public string Origin { get; set; }

        public Dictionary<string, object> ClientExtensions { get; set; }
        public string Type { get; set; }

        public ParsedAttestionObject AttestionObject { get; set; }
        public AuthenticatorAttestationRawResponse Raw { get; private set; }

        public static AuthenticatorAttestationResponse Parse(AuthenticatorAttestationRawResponse rawResponse)
        {
            var stringx = Encoding.UTF8.GetString(rawResponse.Response.ClientDataJson);
            var response = Newtonsoft.Json.JsonConvert.DeserializeObject<AuthenticatorAttestationResponse>(stringx);

            // we will need to access raw in Verify()
            response.Raw = rawResponse;

            var rawAttestionObj = Base64Url.Decode(rawResponse.Response.AttestationObject);
            var cborAttestion = PeterO.Cbor.CBORObject.DecodeFromBytes(rawAttestionObj);
            response.AttestionObject = new ParsedAttestionObject()
            {
                Fmt = cborAttestion["fmt"].AsString(),
                AttStmt = cborAttestion["attStmt"], // convert to dictionary?
                AuthData = cborAttestion["authData"].GetByteString()
            };

            return response;
        }

        public void Verify(OptionsResponse options, string expectedOrigin)
        {
            if (this.Type != "webauthn.create") throw new Fido2VerificationException();

            // verify challenge is same
            if (this.Challenge != options.Challenge) throw new Fido2VerificationException();

            // verify origin
            // todo: This might not be so correct
            if (this.Origin != expectedOrigin) throw new Fido2VerificationException();

            // 6
            //todo:  Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained.If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.

            // 7
            // Compute the hash of response.clientDataJSON using SHA - 256.
            byte[] hashedClientDataJson;
            byte[] hashedRpId;
            using (var sha = SHA256.Create())
            {
                hashedClientDataJson = sha.ComputeHash(this.Raw.Response.ClientDataJson);
                hashedRpId = sha.ComputeHash(Encoding.UTF8.GetBytes(options.Rp.Id));
            }

            // 9 
            // Verify that the RP ID hash in authData is indeed the SHA - 256 hash of the RP ID expected by the RP.
            var hash = AuthDataHelper.GetRpIdHash(this.AttestionObject.AuthData);
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

            // 13
            // Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].
            //
            // 14
            // validate the attStmt

            // A COSEAlgorithmIdentifier containing the identifier of the algorithm used to generate the attestation signature
            var alg = AttestionObject.AttStmt["alg"];
            // A byte string containing the attestation signature
            var sig = AttestionObject.AttStmt["sig"];
            // The elements of this array contain attestnCert and its certificate chain, each encoded in X.509 format
            var x5c = AttestionObject.AttStmt["x5c"];
            // The identifier of the ECDAA-Issuer public key
            var ecdaaKeyId = AttestionObject.AttStmt["ecdaaKeyId"];

            var parsedSignature = AuthDataHelper.ParseSigData(sig.GetByteString());
            if (AttestionObject.Fmt == "fido-u2f")
            {
                // validate format
                if (!(
                    AttestionObject.AttStmt.ContainsKey("x5c") &&
                    AttestionObject.AttStmt.ContainsKey("sig")
                    )) throw new Fido2VerificationException("Format is invalid");

                // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
                if (x5c.Count != 1) throw new Fido2VerificationException();

                // 2a. the attestation certificate attestnCert MUST be the first element in the array
                var cert = new X509Certificate2(x5c.Values.First().GetByteString());

                var pubKey = (ECDsaCng)cert.GetECDsaPublicKey();

                // 2b. If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error
                if (CngAlgorithm.ECDsaP256 != pubKey.Key.Algorithm) throw new Fido2VerificationException();

                // 3. Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData
                var credentialId = AuthDataHelper.GetAttestionData(AttestionObject.AuthData).credId.ToArray();
                var credentialIdPublicKey = AuthDataHelper.GetAttestionData(AttestionObject.AuthData).credentialPublicKey.ToArray();
                // 4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to CTAP1/U2F public Key format
                var x = AuthDataHelper.CoseKeyToU2F(credentialIdPublicKey).x.ToArray();
                var y = AuthDataHelper.CoseKeyToU2F(credentialIdPublicKey).y.ToArray();
                var publicKeyU2F = new byte[1 + x.Length + y.Length];
                publicKeyU2F[0] = 0x4;
                var offset = 1;
                x.CopyTo(publicKeyU2F, offset);
                offset += x.Length;
                y.CopyTo(publicKeyU2F, offset);
                // 5. Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
                var verificationData = new byte[1 + hashedRpId.Length + hashedClientDataJson.Length + credentialId.Length + publicKeyU2F.Length];
                verificationData[0] = 0x00;
                offset = 1;
                hashedRpId.CopyTo(verificationData, offset);
                offset += hashedRpId.Length;
                hashedClientDataJson.CopyTo(verificationData, offset);
                offset += hashedClientDataJson.Length;
                credentialId.CopyTo(verificationData, offset);
                offset += credentialId.Length;
                publicKeyU2F.CopyTo(verificationData, offset);
                // 6. Verify the sig using verificationData and certificate public key
                if (true != pubKey.VerifyData(verificationData, parsedSignature.ToArray(), HashAlgorithmName.SHA256)) throw new Fido2VerificationException();
            }
            /**
             * If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
             */
            if (AttestionObject.Fmt == "packed")
            {
                byte[] data = new byte[AttestionObject.AuthData.Length + hashedClientDataJson.Length];
                AttestionObject.AuthData.CopyTo(data, 0);
                hashedClientDataJson.CopyTo(data, AttestionObject.AuthData.Length);

                // If x5c is present, this indicates that the attestation type is not ECDAA
                if (null != x5c)
                {
                    // The attestation certificate attestnCert MUST be the first element in the array.
                    var cert = new X509Certificate2(x5c.Values.First().GetByteString());
                    // 2a. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
                    // using the attestation public key in attestnCert with the algorithm specified in alg
                    var pubKey = (ECDsaCng)cert.GetECDsaPublicKey(); // attestation public key

                    if (true != pubKey.VerifyData(data, parsedSignature, algLookup[alg.AsInt32()])) throw new Fido2VerificationException();
                    // 2b. Version MUST be set to 3
                    if (3 != cert.Version) throw new Fido2VerificationException();
                    // Subject field MUST contain C, O, OU, CN
                    // OU must match "Authenticator Attestation"
                    var dictSubject = cert.Subject.Split(", ").Select(part => part.Split('=')).ToDictionary(split => split[0], split => split[1]);
                    if (0 == dictSubject["C"].Length ||
                        0 == dictSubject["O"].Length ||
                        0 == dictSubject["OU"].Length ||
                        0 == dictSubject["CN"].Length ||
                        "Authenticator Attestation" != dictSubject["OU"].ToString()) throw new Fido2VerificationException();
                    bool BasicConstraintsFound = false;
                    foreach (var ext in cert.Extensions)
                    {
                        // 2c. If the related attestation root certificate is used for multiple authenticator models, 
                        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING
                        if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.1.1.4")) // id-fido-gen-ce-aaguid
                        {
                            var ms = new System.IO.MemoryStream(ext.RawData.ToArray());
                            // OCTET STRING
                            if (0x4 != ms.ReadByte()) throw new Fido2VerificationException();
                            // AAGUID
                            if (0x10 != ms.ReadByte()) throw new Fido2VerificationException();
                            var btGuid = new byte[0x10];
                            ms.Read(btGuid, 0, 0x10);
                            // verify that the value of this extension matches the aaguid in authenticatorData
                            if (!btGuid.SequenceEqual(AuthDataHelper.GetAttestionData(AttestionObject.AuthData).aaguid.ToArray())) throw new Fido2VerificationException();
                            //The extension MUST NOT be marked as critical
                            if (true == ext.Critical) throw new Fido2VerificationException();
                        }
                        // 2d. // The Basic Constraints extension MUST have the CA component set to false
                        if (ext.Oid.FriendlyName == "Basic Constraints")
                        {
                            BasicConstraintsFound = true;
                            X509BasicConstraintsExtension baseExt = (X509BasicConstraintsExtension)ext;

                            if (true == baseExt.CertificateAuthority) throw new Fido2VerificationException();
                        }
                        // id-fido-u2f-ce-transports 
                        if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.2.1.1"))
                        {
                            var ms = new System.IO.MemoryStream(ext.RawData.ToArray());
                            // BIT STRING
                            if (0x3 != ms.ReadByte()) throw new Fido2VerificationException();
                            if (0x2 != ms.ReadByte()) throw new Fido2VerificationException();
                            var unused = ms.ReadByte(); // unused byte
                            // https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-authenticator-transports-extension-v1.1-id-20160915.html#fido-u2f-certificate-transports-extension
                            var u2ftransports = ms.ReadByte(); // do something with this?
                        }
                    }
                    // The Basic Constraints extension MUST have the CA component set to false
                    if (false == BasicConstraintsFound) throw new Fido2VerificationException();
                }
                // If ecdaaKeyId is present, then the attestation type is ECDAA
                else if (null != ecdaaKeyId)
                {
                    var cert = new X509Certificate2(ecdaaKeyId.GetByteString());
                    var pubKey = (ECDsaCng)cert.GetECDsaPublicKey();
                    if (true != pubKey.VerifyData(data, parsedSignature.ToArray())) throw new Fido2VerificationException();
                }
                // If neither x5c nor ecdaaKeyId is present, self attestation is in use
                else
                {
                    var cert = new X509Certificate2(AuthDataHelper.GetAttestionData(AttestionObject.AuthData).credentialPublicKey.ToArray());
                    var pubKey = (ECDsaCng)cert.GetECDsaPublicKey();
                    // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData
                    if (true != algLookup[alg.AsInt32()].Equals(pubKey.Key.Algorithm)) throw new Fido2VerificationException();
                    // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg
                    if (true != pubKey.VerifyData(data, parsedSignature, algLookup[alg.AsInt32()])) throw new Fido2VerificationException();
                }
            }
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
