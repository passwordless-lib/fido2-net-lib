using System;
using System.Collections.Generic;

namespace fido2NetLib
{

    /// <summary>
    /// Sent to the browser when we want to Assert credentials and authenticate a user
    /// </summary>
    public class AssertionOptions
    {
        public string Challenge { get; set; }
        public uint Timeout { get; set; }
        public string RpId { get; set; }
        public List<object> AllowCredentials { get; set; }
        public string UserVerification { get; set; }

        internal static AssertionOptions Create(byte[] challenge, Fido2NetLib.Configuration config)
        {
            return new AssertionOptions()
            {
                Challenge = Base64Url.Encode(challenge),
                Timeout = config.Timeout,
                RpId = config.ServerDomain
            };
        }

        // todo: Add Extensions
    }
}
