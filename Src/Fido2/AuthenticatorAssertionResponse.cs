using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Fido2NetLib.Objects;

#nullable disable

namespace Fido2NetLib
{
    /// <summary>
    /// The AuthenticatorAssertionResponse interface represents an authenticator's response to a client’s request for generation of a new authentication assertion given the Relying Party's challenge and optional list of credentials it is aware of.
    /// This response contains a cryptographic signature proving possession of the credential private key, and optionally evidence of user consent to a specific transaction.
    /// </summary>
    public sealed class AuthenticatorAssertionResponse : CollectedClientData
    {
        private AuthenticatorAssertionResponse(byte[] clientDataJson) : base(clientDataJson)
        {
        }

        public AuthenticatorAssertionRawResponse Raw { get; init; }

        public byte[] AuthenticatorData { get; init; }

        public byte[] Signature { get; init; }

        public byte[] UserHandle { get; init; }

        public static AuthenticatorAssertionResponse Parse(AuthenticatorAssertionRawResponse rawResponse)
        {
            var response = new AuthenticatorAssertionResponse(rawResponse.Response.ClientDataJson)
            {
                Raw = rawResponse, // accessed in Verify()
                AuthenticatorData = rawResponse.Response.AuthenticatorData,
                Signature = rawResponse.Response.Signature,
                UserHandle = rawResponse.Response.UserHandle
            };

            return response;
        }

        /// <summary>
        /// Implements alghoritm from https://www.w3.org/TR/webauthn/#verifying-assertion
        /// </summary>
        /// <param name="options">The assertion options that was sent to the client</param>
        /// <param name="fullyQualifiedExpectedOrigins">
        /// The expected fully qualified server origins, used to verify that the signature is sent to the expected server
        /// </param>
        /// <param name="storedPublicKey">The stored public key for this CredentialId</param>
        /// <param name="storedSignatureCounter">The stored counter value for this CredentialId</param>
        /// <param name="isUserHandleOwnerOfCredId">A function that returns <see langword="true"/> if user handle is owned by the credential ID</param>
        /// <param name="cancellationToken"></param>
        public async Task<AssertionVerificationResult> VerifyAsync(
            PublicKeyCredentialRequestOptions options,
            HashSet<string> fullyQualifiedExpectedOrigins,
            byte[] storedPublicKey,
            uint storedSignatureCounter,
            IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredId,
            CancellationToken cancellationToken = default)
        {
            BaseVerify(fullyQualifiedExpectedOrigins, options.Challenge);

            if (Raw.Type != PublicKeyCredentialType.PublicKey)
                throw new Fido2VerificationException("AssertionResponse Type is not set to public-key");

            if (Raw.Id is null)
                throw new Fido2VerificationException("Id is missing");

            if (Raw.RawId is null)
                throw new Fido2VerificationException("RawId is missing");

            // 5. If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
            if (options.AllowCredentials != null && options.AllowCredentials.Any())
            {
                // might need to transform x.Id and raw.id as described in https://www.w3.org/TR/webauthn/#publickeycredential
                if (!options.AllowCredentials.Any(x => x.Id.SequenceEqual(Raw.Id)))
                    throw new Fido2VerificationException("Invalid");
            }

            // 6. Identify the user being authenticated and verify that this user is the owner of the public key credential source credentialSource identified by credential.id
            if (UserHandle != null)
            {
                if (UserHandle.Length is 0)
                    throw new Fido2VerificationException("Userhandle was empty DOMString. It should either be null or have a value.");

                if (false == await isUserHandleOwnerOfCredId(new IsUserHandleOwnerOfCredentialIdParams(Raw.Id, UserHandle), cancellationToken))
                {
                    throw new Fido2VerificationException("User is not owner of the public key identitief by the credential id");
                }
            }

            // 7. Using credential’s id attribute(or the corresponding rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key.
            // Credential public key passed in via storePublicKey parameter

            // 8. Let cData, authData and sig denote the value of credential’s response's clientDataJSON, authenticatorData, and signature respectively.
            //var cData = Raw.Response.ClientDataJson;
            var authData = new AuthenticatorData(AuthenticatorData);
            //var sig = Raw.Response.Signature;

            // 9. Let JSONtext be the result of running UTF-8 decode on the value of cData.
            // var JSONtext = Encoding.UTF8.GetBytes(cData.ToString());

            // 10. Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext

            // 11. Verify that the value of C.type is the string webauthn.get.
            if (Type is not "webauthn.get")
                throw new Fido2VerificationException("AssertionResponse is not type webauthn.get");

            // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge
            // 13. Verify that the value of C.origin matches the Relying Party's origin.
            // done in base class

            // 14. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.

            // https://www.w3.org/TR/webauthn/#sctn-appid-extension
            // FIDO AppID Extension:
            // If true, the AppID was used and thus, when verifying an assertion, the Relying Party MUST expect the rpIdHash to be the hash of the AppID, not the RP ID.
            var rpid = Raw.Extensions?.AppID ?? false ? options.Extensions?.AppID : options.RpId;
            byte[] hashedRpId = SHA256.HashData(Encoding.UTF8.GetBytes(rpid ?? string.Empty));

            if (!authData.RpIdHash.SequenceEqual(hashedRpId))
                throw new Fido2VerificationException("Hash mismatch RPID");

            // 15. Verify that the User Present bit of the flags in authData is set.
            if (!authData.UserPresent &&
                // Server-ServerAuthenticatorAssertionResponse-Resp3 Test server processing authenticatorData
                // P-5 Send a valid ServerAuthenticatorAssertionResponse with authenticatorData.flags.UP is set, despite requested userVerification set to "discouraged", and check that server succeeds
                // P-7 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "discouraged", and check that server succeed
                ((options.UserVerification is not UserVerificationRequirement.Discouraged) &&
                // P-4 Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "preferred", and check that server succeeds
                (!(options.UserVerification is UserVerificationRequirement.Preferred && !authData.UserVerified))))
                    throw new Fido2VerificationException("User Present flag not set in authenticator data");

            // 16. If the Relying Party requires user verification for this assertion, verify that the User Verified bit of the flags in authData is set
            if (options.UserVerification is UserVerificationRequirement.Required && !authData.UserVerified) 
                throw new Fido2VerificationException("User verification is required");

            // 18. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
            // todo: Verify this (and implement extensions on options)
            if (authData.HasExtensionsData && (authData.Extensions is null || authData.Extensions.Length is 0)) 
                throw new Fido2VerificationException("Extensions flag present, malformed extensions detected");

            if (!authData.HasExtensionsData && authData.Extensions != null) 
                throw new Fido2VerificationException("Extensions flag not present, but extensions detected");

            // 19. Let hash be the result of computing a hash over the cData using SHA-256.
            byte[] hash = SHA256.HashData(Raw.Response.ClientDataJson);

            // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash
            byte[] data = DataHelper.Concat(Raw.Response.AuthenticatorData, hash);
         
            if (storedPublicKey is null || storedPublicKey.Length is 0) 
                throw new Fido2VerificationException("Stored public key is null or empty");

            var cpk = new CredentialPublicKey(storedPublicKey);

            if (!cpk.Verify(data, Signature)) 
                throw new Fido2VerificationException("Signature did not match");

            // 21. Let storedSignCount be the stored signature counter value associated with credential.id.
            // If authData.signCount is nonzero or storedSignCount is nonzero, then run the following sub-step
            if (authData.SignCount != 0 || storedSignatureCounter != 0)
            {
                // If authData.signCount is greater than storedSignCount, update storedSignCount to be the value of authData.signCount
                if (authData.SignCount > storedSignatureCounter)
                    storedSignatureCounter = authData.SignCount;

                // If authData.signCount is less than or equal to storedSignCount, This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential private key may exist and are being used in parallel.
                // Relying Parties should incorporate this information into their risk scoring. Whether the Relying Party updates storedSignCount in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific
                else if (authData.SignCount <= storedSignatureCounter)
                    throw new Fido2VerificationException("SignatureCounter was not greater than stored SignatureCounter");
            }

            // 22. If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.
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
