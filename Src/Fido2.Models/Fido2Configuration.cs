﻿using System.Net.Http;

namespace Fido2NetLib
{
    public class Fido2Configuration
    {
        /// <summary>
        /// This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete. 
        /// This is treated as a hint, and MAY be overridden by the client.
        /// </summary>
        public uint Timeout { get; set; } = 60000;

        /// <summary>
        /// TimestampDriftTolerance specifies a time in milliseconds that will be allowed for clock drift on a timestamped attestation.
        /// </summary>
        public int TimestampDriftTolerance { get; set; } = 0; //Pretty sure 0 will never work - need a better default?

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
        /// MDSAccessKey
        /// </summary>
        public string MDSAccessKey { get; set; }

        /// <summary>
        /// MDSCacheDirPath
        /// </summary>
        public string MDSCacheDirPath { get; set; }

        /// <summary>
        /// Create the configuration for Fido2
        /// </summary>
        public Fido2Configuration()
        {
        }
    }
}
