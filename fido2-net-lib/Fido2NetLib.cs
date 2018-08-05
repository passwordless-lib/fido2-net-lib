using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace fido2NetLib
{
    public class Fido2NetLib
    {
        // todo: should not be object
        static ConcurrentDictionary<string, object> globalAttestationMap = new ConcurrentDictionary<string, object>();
        public class Configuration
        {
            public uint Timeout { get; set; } = 60000;
            public int ChallengeSize { get; set; } = 64;
            public string ServerDomain { get; set; }
            public string ServerName { get; set; }
            public string ServerIcon { get; set; }
            public string Origin { get; set; }
        }

        private Configuration Config { get; }

        private RandomNumberGenerator _crypto;

        public Fido2NetLib(Configuration config)
        {
            Config = config;
            _crypto = RandomNumberGenerator.Create();

        }

        /// <summary>
        /// Returns CredentialCreateOptions including a challenge to be sent to the browser/authr to create new credentials
        /// </summary>
        /// <returns></returns>
        public CredentialCreateOptions RequestNewCredential(User user, string requestedAttesstation)
        {
            // https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
            // challenge.rp
            // challenge.user
            // challenge.excludeCredentials
            // challenge.authenticatorSelection
            // challenge.attestation
            // challenge.extensions

            // note: I have no idea if this crypto is ok...
            var challenge = new byte[this.Config.ChallengeSize];
            _crypto.GetBytes(challenge);

            //var options = new OptionsResponse()
            //{
            //    Challenge = challenge.ToString(), //?
            //    Timeout = this.Config.Timeout
            //};

            var options = CredentialCreateOptions.Create(challenge, this.Config);
            options.User = user;
            options.Attestation = requestedAttesstation;

            return options;
        }

        /// <summary>
        /// Verifies the response from the browser/authr after creating new credentials
        /// </summary>
        /// <param name="attestionResponse"></param>
        /// <param name="origChallenge"></param>
        /// <returns></returns>
        public CreationResult MakeNewCredential(AuthenticatorAttestationRawResponse attestionResponse, CredentialCreateOptions origChallenge)
        {
            var parsedResponse = AuthenticatorAttestationResponse.Parse(attestionResponse);
            parsedResponse.Verify(origChallenge, this.Config.Origin);

            // todo: Set Errormessage etc.
            return new CreationResult { Status = "ok", ErrorMessage = "" };
        }

        /// <summary>
        /// Returns XOptions including a challenge to the browser/authr to assert existing credentials and authenticate a user.
        /// </summary>
        /// <returns></returns>
        public AssertionOptions GetAssertion(User user, List<PublicKeyCredentialDescriptor> allowedCredentials)
        {

            var challenge = new byte[this.Config.ChallengeSize];
            _crypto.GetBytes(challenge);

            //var options = new OptionsResponse()
            //{
            //    Challenge = challenge.ToString(), //?
            //    Timeout = this.Config.Timeout
            //};

            var options = AssertionOptions.Create(challenge, allowedCredentials, this.Config);

            return options;


        }

        /// <summary>
        /// Verifies the assertion response from the browser/authr to assert existing credentials and authenticate a user.
        /// </summary>
        /// <returns></returns>
        public bool MakeAssertion(AuthenticatorAssertionRawResponse assertionResponse, AssertionOptions origOptions, ECDsaCng existingPublicKey)
        {
            var parsedResponse = AuthenticatorAssertionResponse.Parse(assertionResponse);
            parsedResponse.Verify(origOptions, this.Config.Origin, 0, false, existingPublicKey);

            return true;
        }

        public static byte[] StringToByteArray(String hex)
        {
            hex = hex.Replace("-", "");
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }





        public class CreationResult
        {
            public string Status { get; set; }
            public string ErrorMessage { get; set; }

            // todo: add debuginfo?
        }

        ///// <summary>
        ///// Processes the makeCredential response
        ///// </summary>
        //public void CreateCredentialResponse(res, expectedChallenge, expectedOrigin, expectedFactor)
        //{

        //}


    }
}
