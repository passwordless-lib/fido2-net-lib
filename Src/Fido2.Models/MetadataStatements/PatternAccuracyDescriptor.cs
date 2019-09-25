using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// The PatternAccuracyDescriptor describes relevant accuracy/complexity aspects in the case that a pattern is used as the user verification method.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#patternaccuracydescriptor-dictionary"/>
    /// </remarks>
    public class PatternAccuracyDescriptor
    {
        /// <summary>
        /// Gets or sets the number of possible patterns (having the minimum length) out of which exactly one would be the right one, i.e. 1/probability in the case of equal distribution.
        /// </summary>
        [JsonProperty("minComplexity", Required = Required.Always)]
        public ulong MinComplexity { get; set; }

        /// <summary>
        /// Gets or sets maximum number of false attempts before the authenticator will block authentication using this method (at least temporarily). 0 means it will never block.
        /// </summary>
        [JsonProperty("maxRetries")]
        public ushort MaxRetries { get; set; }

        /// <summary>
        /// Gets or sets the enforced minimum number of seconds wait time after blocking (due to forced reboot or similar mechanism).
        /// <para>
        /// 0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded. 
        /// All alternative user verification methods MUST be specified appropriately in the metadata under userVerificationDetails.
        /// </para>
        /// </summary>
        [JsonProperty("blockSlowdown")]
        public ushort BlockSlowdown { get; set; }
    }
}
