using System;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// A WebAuthn Relying Party may require user verification for some of its operations but not for others, and may use this type to express its needs.
    /// </summary>
    public sealed class UserVerificationRequirement : TypedString
    {
        /// <summary>
        /// This value indicates that the Relying Party requires user verification for the operation and will fail the operation if the response does not have the UV flag set.
        /// </summary>
        public static readonly UserVerificationRequirement Required = new UserVerificationRequirement("required");
        /// <summary>
        /// This value indicates that the Relying Party prefers user verification for the operation if possible, but will not fail the operation if the response does not have the UV flag set.
        /// </summary>
        public static readonly UserVerificationRequirement Preferred = new UserVerificationRequirement("preferred");

        /// <summary>
        /// This value indicates that the Relying Party does not want user verification employed during the operation(e.g., in the interest of minimizing disruption to the user interaction flow).
        /// </summary>
        public static readonly UserVerificationRequirement Discouraged = new UserVerificationRequirement("discouraged");

        private UserVerificationRequirement(string value) : base(value)
        {
        }

        public static UserVerificationRequirement Parse(string value)
        {
            switch (value)
            {
                case "required":
                    return Required;
                case "preferred":
                    return Preferred;
                case "discouraged":
                    return Discouraged;
                default:
                    throw new InvalidOperationException("Could not parse value");
            }
        }
    }
}
