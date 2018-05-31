using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace fido2NetLib
{

    /// <summary>
    /// The AuthenticatorAttestationResponse interface represents the authenticator's response to a client’s request for the creation of a new public key credential.
    /// It contains information about the new credential that can be used to identify it for later use, and metadata that can be used by the Relying Party to assess the characteristics of the credential during registration.
    /// </summary>
    public class AuthenticatorAttestationResponse
    {
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
            // todo: implement

            // 12
            // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected
            // todo: Implement sort of like this: ClientExtensions.Keys.Any(x => options.extensions.contains(x);

            // 13
            // Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].

            // 14
            // validate the attStmt

            /**
             * If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
*/

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
