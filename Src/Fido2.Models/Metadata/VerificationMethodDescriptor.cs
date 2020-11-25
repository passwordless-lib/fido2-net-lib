﻿using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// A descriptor for a specific base user verification method as implemented by the authenticator.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#verificationmethoddescriptor-dictionary"/>
    /// </remarks>
    public class VerificationMethodDescriptor
    {
        /// <summary>
        /// Gets or sets a single USER_VERIFY constant, not a bit flag combination. 
        /// </summary>
        /// <remarks>
        /// This value MUST be non-zero.
        /// </remarks>
        [JsonProperty("userVerification", Required = Required.Always)]
        public ulong UserVerification { get; set; }
        /// <summary>
        /// Gets or sets a may optionally be used in the case of method USER_VERIFY_PASSCODE.
        /// </summary>
        [JsonProperty("caDesc")]
        public CodeAccuracyDescriptor CaDesc { get; set; }
        /// <summary>
        /// Gets or sets a may optionally be used in the case of method USER_VERIFY_FINGERPRINT, USER_VERIFY_VOICEPRINT, USER_VERIFY_FACEPRINT, USER_VERIFY_EYEPRINT, or USER_VERIFY_HANDPRINT.
        /// </summary>
        [JsonProperty("baDesc")]
        public BiometricAccuracyDescriptor BaDesc { get; set; }
        /// <summary>
        /// Gets or sets a may optionally be used in case of method USER_VERIFY_PATTERN.
        /// </summary>
        [JsonProperty("paDesc")]
        public PatternAccuracyDescriptor PaDesc { get; set; }
    }
}
