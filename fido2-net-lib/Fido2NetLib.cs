using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    /// <summary>
    /// Public API for parsing and veriyfing FIDO2 attestation & assertion responses.
    /// </summary>
    public class Fido2
    {
        public class Configuration
        {
            /// <summary>
            /// This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.This is treated as a hint, and MAY be overridden by the client
            /// </summary>
            public uint Timeout { get; set; } = 60000;

            /// <summary>
            /// The size of the challenges sent to the client
            /// </summary>
            public int ChallengeSize { get; set; } = 16;

            /// <summary>
            /// The effetive domain of the RP. Should be unique and will be used as the identity for the RP.
            /// </summary>
            public string ServerDomain { get; set; }

            /// <summary>
            ///  A human friendly name of the RP
            /// </summary>
            public string ServerName { get; set; }

            /// <summary>
            /// A serialized URL which resolves to an image associated with the entity.For example, this could be a user’s avatar or a Relying Party's logo. This URL MUST be an a priori authenticated URL. Authenticators MUST accept and store a 128-byte minimum length for an icon member’s value. Authenticators MAY ignore an icon member’s value if its length is greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches of the URL, at the cost of needing more storage.
            /// </summary>
            public string ServerIcon { get; set; }

            /// <summary>
            /// Server origin, including protocol host and port.
            /// </summary>
            public string Origin { get; set; }

            /// <summary>
            /// MetdataService to verify metadata statements https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-service-v2.0-rd-20180702.html
            /// </summary>
            public IMetadataService MetadataService { get; set; }

            /// <summary>
            /// Create the configuration for Fido2
            /// </summary>
            public Configuration()
            {
            }

            public Configuration(IMetadataService metadataService)
            {
                MetadataService = metadataService;
            }
        }

        private Configuration Config { get; }

        private RandomNumberGenerator _crypto;

        public Fido2(Configuration config)
        {
            Config = config;
            _crypto = RandomNumberGenerator.Create();
        }

        /// <summary>
        /// Returns CredentialCreateOptions including a challenge to be sent to the browser/authr to create new credentials
        /// </summary>
        /// <returns></returns>
        /// <param name="excludeCredentials">Recommended. This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator.The client is requested to return an error if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.</param>
        public CredentialCreateOptions RequestNewCredential(User user, List<PublicKeyCredentialDescriptor> excludeCredentials)
        {
            return RequestNewCredential(user, excludeCredentials, AuthenticatorSelection.Default, AttestationConveyancePreference.None);
        }

        /// <summary>
        /// Returns CredentialCreateOptions including a challenge to be sent to the browser/authr to create new credentials
        /// </summary>
        /// <returns></returns>
        /// <param name="attestationPreference">This member is intended for use by Relying Parties that wish to express their preference for attestation conveyance. The default is none.</param>
        /// <param name="excludeCredentials">Recommended. This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator.The client is requested to return an error if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.</param>
        public CredentialCreateOptions RequestNewCredential(User user, List<PublicKeyCredentialDescriptor> excludeCredentials, AuthenticatorSelection authenticatorSelection, AttestationConveyancePreference attestationPreference)
        {
            // note: I have no idea if this crypto is ok...
            var challenge = new byte[Config.ChallengeSize];
            _crypto.GetBytes(challenge);

            var options = CredentialCreateOptions.Create(Config, challenge, user, authenticatorSelection, attestationPreference, excludeCredentials);
            return options;
        }

        /// <summary>
        /// Verifies the response from the browser/authr after creating new credentials
        /// </summary>
        /// <param name="attestationResponse"></param>
        /// <param name="origChallenge"></param>
        /// <returns></returns>
        public async Task<CredentialMakeResult> MakeNewCredentialAsync(AuthenticatorAttestationRawResponse attestationResponse, CredentialCreateOptions origChallenge, IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser, byte[] requestTokenBindingId = null)
        {
            var parsedResponse = AuthenticatorAttestationResponse.Parse(attestationResponse);
            var success = await parsedResponse.VerifyAsync(origChallenge, Config.Origin, isCredentialIdUniqueToUser, Config.MetadataService, requestTokenBindingId);

            // todo: Set Errormessage etc.
            return new CredentialMakeResult { Status = "ok", ErrorMessage = string.Empty, Result = success };
        }

        /// <summary>
        /// Returns AssertionOptions including a challenge to the browser/authr to assert existing credentials and authenticate a user.
        /// </summary>
        /// <returns></returns>
        public AssertionOptions GetAssertionOptions(IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials, UserVerificationRequirement userVerification, AuthenticationExtensionsClientOutputs extensions = null)
        {
            var challenge = new byte[Config.ChallengeSize];
            _crypto.GetBytes(challenge);

            var options = AssertionOptions.Create(Config, challenge, allowedCredentials, userVerification, extensions);
            return options;
        }

        /// <summary>
        /// Verifies the assertion response from the browser/authr to assert existing credentials and authenticate a user.
        /// </summary>
        /// <returns></returns>
        public async Task<AssertionVerificationResult> MakeAssertionAsync(AuthenticatorAssertionRawResponse assertionResponse, AssertionOptions originalOptions, byte[] storedPublicKey, uint storedSignatureCounter, IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredentialIdCallback, byte[] requestTokenBindingId = null)
        {
            var parsedResponse = AuthenticatorAssertionResponse.Parse(assertionResponse);

            var result = await parsedResponse.VerifyAsync(originalOptions, Config.Origin, storedPublicKey, storedSignatureCounter, isUserHandleOwnerOfCredentialIdCallback, requestTokenBindingId);

            return result;
        }

        /// <summary>
        /// Result of parsing and verifying attestation. Used to transport Public Key back to RP
        /// </summary>
        public class CredentialMakeResult : Fido2ResponseBase
        {
            public AttestationVerificationSuccess Result { get; internal set; }

            // todo: add debuginfo?
        }
    }

    /// <summary>
    /// Callback function used to validate that the CredentialID is unique to this User
    /// </summary>
    /// <param name="credentialIdUserParams"></param>
    /// <returns></returns>
    public delegate Task<bool> IsCredentialIdUniqueToUserAsyncDelegate(IsCredentialIdUniqueToUserParams credentialIdUserParams);
    /// <summary>
    /// Callback function used to validate that the Userhandle is indeed owned of the CrendetialId
    /// </summary>
    /// <param name="credentialIdUserHandleParams"></param>
    /// <returns></returns>
    public delegate Task<bool> IsUserHandleOwnerOfCredentialIdAsync(IsUserHandleOwnerOfCredentialIdParams credentialIdUserHandleParams);
}
