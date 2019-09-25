using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// The CodeAccuracyDescriptor describes the relevant accuracy/complexity aspects of passcode user verification methods.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#codeaccuracydescriptor-dictionary"/>
    /// </remarks>
    public class CodeAccuracyDescriptor
    {
        /// <summary>
        /// Gets or sets the numeric system base (radix) of the code, e.g.  10 in the case of decimal digits. 
        /// </summary>
        [JsonProperty("base", Required = Required.Always)]
        public ushort Base { get; set; }
        /// <summary>
        /// Gets or sets the minimum number of digits of the given base required for that code, e.g. 4 in the case of 4 digits.
        /// </summary>
        [JsonProperty("minLength", Required = Required.Always)]
        public ushort MinLength { get; set; }
        /// <summary>
        /// Gets or sets the maximum number of false attempts before the authenticator will block this method (at least for some time).
        /// <para>0 means it will never block.</para>
        /// </summary>
        [JsonProperty("maxRetries")]
        public ushort MaxRetries { get; set; }
        /// <summary>
        /// Gets or sets the enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar). 
        /// <para>0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded.</para> 
        /// <para>All alternative user verification methods MUST be specified appropriately in the Metadata in userVerificationDetails.</para> 
        /// </summary>
        [JsonProperty("blockSlowdown")]
        public ushort BlockSlowdown { get; set; }
    }
}
