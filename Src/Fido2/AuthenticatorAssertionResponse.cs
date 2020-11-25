﻿using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib.Objects;

namespace Fido2NetLib
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
        public byte[] UserHandle { get; set; }

        public static AuthenticatorAssertionResponse Parse(AuthenticatorAssertionRawResponse rawResponse)
        {
            var response = new AuthenticatorAssertionResponse(rawResponse.Response.ClientDataJson)
            {
                // we will need to access raw in Verify()
                Raw = rawResponse,
                AuthenticatorData = rawResponse.Response.AuthenticatorData,
                Signature = rawResponse.Response.Signature,
                UserHandle = rawResponse.Response.UserHandle
            };

            return response;
        }


        /// <summary>
        /// Implements alghoritm from https://www.w3.org/TR/webauthn/#verifying-assertion
        /// </summary>
        /// <param name="options">The assertionoptions that was sent to the client</param>
        /// <param name="expectedOrigin">
        /// The expected server origin, used to verify that the signature is sent to the expected server
        /// </param>
        /// <param name="storedPublicKey">The stored public key for this CredentialId</param>
        /// <param name="storedSignatureCounter">The stored counter value for this CredentialId</param>
        /// <param name="isUserHandleOwnerOfCredId">A function that returns <see langword="true"/> if user handle is owned by the credential ID</param>
        /// <param name="requestTokenBindingId"></param>
        public async Task<AssertionVerificationResult> VerifyAsync(
            AssertionOptions options,
            string expectedOrigin,
            byte[] storedPublicKey,
            uint storedSignatureCounter,
            IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredId,
            byte[] requestTokenBindingId)
        {
            BaseVerify(expectedOrigin, options.Challenge, requestTokenBindingId);

            if (Raw.Type != PublicKeyCredentialType.PublicKey)
                throw new Fido2VerificationException("AssertionResponse Type is not set to public-key");

            if (Raw.Id == null)
                throw new Fido2VerificationException("Id is missing");
            if (Raw.RawId == null)
                throw new Fido2VerificationException("RawId is missing");

            // 1. If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
            if (options.AllowCredentials != null && options.AllowCredentials.Count() > 0)
            {
                // might need to transform x.Id and raw.id as described in https://www.w3.org/TR/webauthn/#publickeycredential
                if (!options.AllowCredentials.Any(x => x.Id.SequenceEqual(Raw.Id)))
                    throw new Fido2VerificationException("Invalid");
            }

            // 2. Identify the user being authenticated and verify that this user is the owner of the public key credential source credentialSource identified by credential.id
            if (UserHandle != null)
            {
                if (UserHandle.Length == 0)
                    throw new Fido2VerificationException("Userhandle was empty DOMString. It should either be null or have a value.");

                if (false == await isUserHandleOwnerOfCredId(new IsUserHandleOwnerOfCredentialIdParams(Raw.Id, UserHandle)))
                {
                    throw new Fido2VerificationException("User is not owner of the public key identitief by the credential id");
                }
            }

            // 3. Using credential’s id attribute(or the corresponding rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key.
            // Credential public key passed in via storePublicKey parameter

            // 4. Let cData, authData and sig denote the value of credential’s response's clientDataJSON, authenticatorData, and signature respectively.
            //var cData = Raw.Response.ClientDataJson;
            var authData = new AuthenticatorData(AuthenticatorData);
            //var sig = Raw.Response.Signature;

            // 5. Let JSONtext be the result of running UTF-8 decode on the value of cData.
            //var JSONtext = Encoding.UTF8.GetBytes(cData.ToString());


            // 7. Verify that the value of C.type is the string webauthn.get.
            if (Type != "webauthn.get")
                throw new Fido2VerificationException("AssertionResponse is not type webauthn.get");

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
                // https://www.w3.org/TR/webauthn/#sctn-appid-extension
                // FIDO AppID Extension:
                // If true, the AppID was used and thus, when verifying an assertion, the Relying Party MUST expect the rpIdHash to be the hash of the AppID, not the RP ID.
                var rpid = Raw.Extensions?.AppID ?? false ? options.Extensions?.AppID : options.RpId;
                hashedRpId = sha.ComputeHash(Encoding.UTF8.GetBytes(rpid ?? string.Empty));
                // 15
                hashedClientDataJson = sha.ComputeHash(Raw.Response.ClientDataJson);
            }

            if (false == authData.RpIdHash.SequenceEqual(hashedRpId))
                throw new Fido2VerificationException("Hash mismatch RPID");
            // 12. Verify that the User Present bit of the flags in authData is set.
            // UNLESS...userVerification is set to preferred or discouraged?
            // See Server-ServerAuthenticatorAssertionResponse-Resp3 Test server processing authenticatorData
            // P-5 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "preferred", and check that server succeeds
            // P-8 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "discouraged", and check that server succeeds
            //if ((false == authData.UserPresent) && (options.UserVerification != UserVerificationRequirement.Discouraged && options.UserVerification != UserVerificationRequirement.Preferred)) throw new Fido2VerificationException("User Present flag not set in authenticator data");

            // 13 If user verification is required for this assertion, verify that the User Verified bit of the flags in aData is set.
            // UNLESS...userPresent is true?
            // see ee Server-ServerAuthenticatorAssertionResponse-Resp3 Test server processing authenticatorData
            // P-8 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "discouraged", and check that server succeeds
            if (UserVerificationRequirement.Required == options.UserVerification && false == authData.UserVerified) 
                throw new Fido2VerificationException("User verification is required");

            // 14. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the get() call.In particular, any extension identifier values in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
            // todo: Verify this (and implement extensions on options)
            if (true == authData.HasExtensionsData && ((null == authData.Extensions) || (0 == authData.Extensions.Length))) 
                throw new Fido2VerificationException("Extensions flag present, malformed extensions detected");
            if (false == authData.HasExtensionsData && (null != authData.Extensions)) 
                throw new Fido2VerificationException("Extensions flag not present, but extensions detected");

            // 15.
            // Done earlier, hashedClientDataJson

            // 16. Using the credential public key looked up in step 3, verify that sig is a valid signature over the binary concatenation of aData and hash.
            byte[] data = new byte[Raw.Response.AuthenticatorData.Length + hashedClientDataJson.Length];
            Buffer.BlockCopy(Raw.Response.AuthenticatorData, 0, data, 0, Raw.Response.AuthenticatorData.Length);
            Buffer.BlockCopy(hashedClientDataJson, 0, data, Raw.Response.AuthenticatorData.Length, hashedClientDataJson.Length);

            if (null == storedPublicKey || 0 == storedPublicKey.Length) 
                throw new Fido2VerificationException("Stored public key is null or empty");
            var cpk = new CredentialPublicKey(storedPublicKey);
            if (true != cpk.Verify(data, Signature)) 
                throw new Fido2VerificationException("Signature did not match");

            // 17.
            if (authData.SignCount > 0 && authData.SignCount <= storedSignatureCounter)
                throw new Fido2VerificationException("SignatureCounter was not greater than stored SignatureCounter");

            return new AssertionVerificationResult()
            {
                Status = "ok",
                ErrorMessage = string.Empty,
                CredentialId = Raw.Id,
                Counter = authData.SignCount,
            };
        }
    }
}
