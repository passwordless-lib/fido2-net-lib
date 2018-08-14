using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace fido2NetLib
{
    /// <summary>
    /// The AuthenticatorAssertionResponse interface represents an authenticator's response to a client’s request for generation of a new authentication assertion given the Relying Party's challenge and optional list of credentials it is aware of.
    /// This response contains a cryptographic signature proving possession of the credential private key, and optionally evidence of user consent to a specific transaction.
    /// </summary>
    public class AuthenticatorAssertionResponse : AuthenticatorResponse
    {
        private AuthenticatorAssertionResponse(byte[] clientDataJson) : base(clientDataJson)
        {

        }

        public AuthenticatorAssertionRawResponse Raw { get; set; }

        public byte[] AuthenticatorData { get; set; }
        public byte[] Signature { get; set; }
        public string UserHandle { get; set; }

        internal static AuthenticatorAssertionResponse Parse(AuthenticatorAssertionRawResponse rawResponse)
        {
            var response = new AuthenticatorAssertionResponse(rawResponse.Response.ClientDataJson)
            {
                // we will need to access raw in Verify()
                Raw = rawResponse,
                AuthenticatorData = rawResponse.Response.AuthenticatorData,
                Signature = AuthDataHelper.ParseSigData(rawResponse.Response.Signature).ToArray()
            };

            return response;
        }


        /// <summary>
        /// Implements alghoritm from https://www.w3.org/TR/webauthn/#verifying-assertion
        /// </summary>
        /// <param name="options"></param>
        /// <param name="expectedOrigin"></param>
        /// <param name="storedCounter"></param>
        public void Verify(AssertionOptions options, string expectedOrigin, uint storedSignatureCounter, bool isUserVerificationRequired, byte[] storedPublicKey, byte[] requestTokenBindingId, Fido2NetLib.isUserHandleOwnerOfCredentialId isUserHandleOwnerOfCredId, Fido2NetLib.StoreSignatureCounter storeSignatureCounterCallback)
        {
            BaseVerify(expectedOrigin, options.Challenge, requestTokenBindingId);


            // 1. If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
            if (options.AllowCredentials != null && options.AllowCredentials.Count > 0)
            {
                // might need to transform x.Id and raw.id as described in https://www.w3.org/TR/webauthn/#publickeycredential
                if (!options.AllowCredentials.Exists(x => x.Id.SequenceEqual(Raw.Id))) throw new Fido2VerificationException();
            }

            // 2. If credential.response.userHandle is present, verify that the user identified by this value is the owner of the public key credential identified by credential.id.
            if (UserHandle != null)
            {
                if (false == isUserHandleOwnerOfCredId(Raw.Id, UserHandle))
                {
                    throw new Fido2VerificationException("User is not owner of the public key identitief by the credential id");
                }
            }

            // 3. Using credential’s id attribute(or the corresponding rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key.
            // public key inserted via parameter.

            // 7. Verify that the value of C.type is the string webauthn.get.
            if (Type != "webauthn.get") throw new Fido2VerificationException();

            // 8. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
            // 9. Verify that the value of C.origin matches the Relying Party's origin.
            // done in base class

            //10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the attestation was obtained.If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
            // Validated in BaseVerify.
            // todo: Needs testing

            // 11. Verify that the rpIdHash in aData is the SHA - 256 hash of the RP ID expected by the Relying Party.

            byte[] hashedClientDataJson;
            byte[] hashedRpId;
            using (var sha = SHA256.Create())
            {
                // 11
                hashedRpId = sha.ComputeHash(Encoding.UTF8.GetBytes(options.RpId));
                // 15
                hashedClientDataJson = sha.ComputeHash(Raw.Response.ClientDataJson);
            }

            var hash = AuthDataHelper.GetRpIdHash(AuthenticatorData);
            if (!hash.SequenceEqual(hashedRpId)) throw new Fido2VerificationException();

            // 12 If user verification is required for this assertion, verify that the User Verified bit of the flags in aData is set.
            var userIsVerified = AuthDataHelper.IsUserVerified(AuthenticatorData);
            if (isUserVerificationRequired && !userIsVerified) throw new Fido2VerificationException();

            // 13. If user verification is not required for this assertion, verify that the User Present bit of the flags in aData is set.
            if (!isUserVerificationRequired)
            {
                if (!AuthDataHelper.IsUserPresent(AuthenticatorData)) throw new Fido2VerificationException();
            }

            // 14. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the get() call.In particular, any extension identifier values in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
            // todo: Verify this (and implement extensions on options)

            // 15.
            // Done earlier

            // 16. Using the credential public key looked up in step 3, verify that sig is a valid signature over the binary concatenation of aData and hash.
            var concatedBytes = Raw.Response.AuthenticatorData.Concat(hashedClientDataJson).ToArray();

            // todo: Add support for more keyformats (https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples)
            var u2fFormattedKey = AuthDataHelper.U2FKeyFromCOSEKey(PeterO.Cbor.CBORObject.DecodeFromBytes(storedPublicKey));
            var pubKey = LoadPublicKey(u2fFormattedKey.publicKeyU2F.Span);

            // note: is this ok? At least it works.
            var pubKeyAlgo = $"{pubKey.SignatureAlgorithm.ToUpperInvariant()}_P{pubKey.KeySize}";

            if (CngAlgorithm.ECDsaP256.ToString() != pubKeyAlgo) throw new Fido2VerificationException();

            var signatureMatch = pubKey.VerifyData(concatedBytes, Signature, HashAlgorithmName.SHA256);
            if (!signatureMatch) throw new Fido2VerificationException("Signature did not match");

            // 17.
            var counter = AuthDataHelper.GetSignCount(AuthenticatorData);
            if(counter <= storedSignatureCounter)
            {
                throw new Fido2VerificationException("SignatureCounter was not greather than storedC SignatureCounter");
            }
            storeSignatureCounterCallback(Raw.Id, counter);
        }

        /// <summary>
        /// Parses the bytes to a ECDSa signature alg
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        private static ECDsa LoadPublicKey(Span<byte> key)
        {
            // .net ECDsa expects two 32 byte arays for X/Y.
            // skip first byte which should alawys be (0x4).
            var pubKeyX = key.Slice(1, 32);
            var pubKeyY = key.Slice(33, 32);

            // add support for more than nistp256 by checking alg (https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples)
            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = pubKeyX.ToArray(),
                    Y = pubKeyY.ToArray()
                }
            });
        }
    }
}
