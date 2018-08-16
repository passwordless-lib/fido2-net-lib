using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{
    public sealed class UserVerificationRequirement : TypedString
    {
        public static readonly UserVerificationRequirement Required = new UserVerificationRequirement("required");
        public static readonly UserVerificationRequirement Preferred = new UserVerificationRequirement("preferred");
        public static readonly UserVerificationRequirement Discouraged = new UserVerificationRequirement("discouraged");

        [JsonConstructor]
        private UserVerificationRequirement(string value) : base(value)
        {
        }
    }
}
