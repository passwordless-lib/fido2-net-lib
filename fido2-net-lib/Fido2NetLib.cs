using System;
using System.Collections.Concurrent;
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
            public int Timeout { get; set; } = 60000;
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
        /// Gets a challenge and any other parameters for the credentials.create() call
        /// </summary>
        /// <returns></returns>
        public OptionsResponse CreateCredentialChallenge(User user)
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

            var options = OptionsResponse.Create(challenge, this.Config);
            options.User = user;

            return options;
        }

        public CreationResult CreateCredentialResult(AuthenticatorAttestationRawResponse attestionResponse, OptionsResponse origChallenge)
        {
            var parsedResponse = AuthenticatorAttestationResponse.Parse(attestionResponse);
            parsedResponse.Verify(origChallenge, this.Config.Origin);

            // todo: Set Errormessage etc.
            return new CreationResult { Status = "ok", ErrorMessage = "" };
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
