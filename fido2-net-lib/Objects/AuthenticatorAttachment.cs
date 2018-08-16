using System;
using System.Collections.Generic;
using System.Text;
using Fido2NetLib;
using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// This enumeration’s values describe authenticators' attachment modalities. Relying Parties use this for two purposes:
    /// to express a preferred authenticator attachment modality when calling navigator.credentials.create() to create a credential, and
    /// to inform the client of the Relying Party's best belief about how to locate the managing authenticators of the credentials listed in allowCredentials when calling navigator.credentials.get().
    /// </summary>
    /// <remarks>
    /// Note: An authenticator attachment modality selection option is available only in the [[Create]](origin, options, sameOriginWithAncestors) operation. The Relying Party may use it to, for example, ensure the user has a roaming credential for authenticating on another client device; or to specifically register a platform credential for easier reauthentication using a particular client device. The [[DiscoverFromExternalSource]](origin, options, sameOriginWithAncestors) operation has no authenticator attachment modality selection option, so the Relying Party SHOULD accept any of the user’s registered credentials. The client and user will then use whichever is available and convenient at the time.
    /// </remarks>
    public sealed class AuthenticatorAttachment : TypedString
    {
        /// <summary>
        /// This value indicates platform attachment
        /// </summary>
        public static readonly AuthenticatorAttachment Platform = new AuthenticatorAttachment("platform");
        /// <summary>
        /// This value indicates cross-platform attachment.
        /// </summary>
        public static readonly AuthenticatorAttachment CrossPlatform = new AuthenticatorAttachment("cross-platform");

        [JsonConstructor]
        private AuthenticatorAttachment(string value) : base(value)
        {
        }
    }
}
